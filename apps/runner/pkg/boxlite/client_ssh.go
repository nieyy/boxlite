// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package boxlite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	boxlitesdk "github.com/boxlite-ai/boxlite/sdks/go"
	"github.com/boxlite-ai/runner/pkg/sshport"
)

// sshCapable is the subset of *boxlite.Box used by SSH access management.
// Defined as an interface so tests can inject fakes without a real VM runtime.
type sshCapable interface {
	EnableSSH(ctx context.Context, authorizedKeys []string, unixUser string) error
	// DisableSSH stops sshd and cleans up files for the exact unix_user that
	// was enabled. Passing the wrong user leaves a restart-recovery marker on
	// disk; the guest default is "boxlite".
	DisableSSH(ctx context.Context, unixUser string) error
	// EnsureSSH verifies that sshd is listening on port 22222 inside the
	// guest and starts it if not. Called by ReapplySSHPortForward after
	// re-adding the gvproxy rule so ForwardHealthy is only set to true when
	// the guest-side peer is confirmed running. The unixUser parameter is
	// carried for context; the underlying script does not require it because
	// it only checks the listener, not the user.
	EnsureSSH(ctx context.Context) error
}

// SSHState holds runtime SSH access state for a single box.
type SSHState struct {
	HostPort int
	UnixUser string
	// AuthorizedKeys stores the exact key set that was last applied to the
	// guest. EnableSSHAccess compares incoming keys against this slice to
	// distinguish true idempotent retries from key-rotation requests.
	// nil means the state is degraded (initial enable failed mid-way).
	AuthorizedKeys []string
	// ForwardHealthy is true when the gvproxy port forward is known to be
	// active. It is set to false by ReapplySSHPortForward when the admin
	// call fails (e.g. gvproxy socket not yet ready after restart). A
	// subsequent idempotent enable_ssh call checks this field and re-applies
	// the forward before returning success, so callers never receive a port
	// that is reported as enabled but unreachable.
	ForwardHealthy bool
	// DisablePending is set when a DisableSSHAccess call successfully removed
	// the gvproxy port forward (host exposure gone) but the guest RPC
	// (stop sshd / remove marker) failed. The port is still allocated and
	// the state is kept so a later retry can finish the guest cleanup.
	//
	// While DisablePending is true:
	//   - ReapplySSHPortForward must NOT re-add the gvproxy forward; the
	//     caller explicitly requested disable and partial success must not
	//     be silently undone by a box restart.
	//   - DisableSSHAccess retries only the guest RPC; on success it removes
	//     state and releases the port (no second unexpose needed).
	//   - EnableSSHAccess proceeds through the full allocation path, but first
	//     calls DisableSSH for the old UnixUser when the new request targets a
	//     different user. This ensures the old user's guest marker is cleared
	//     before the new user is enabled; skipping this step would leave two
	//     users' markers on disk and restart recovery could resurrect the old
	//     user's credentials.
	DisablePending bool
	// InternalBoxID is the boxlite-internal short ID (e.g. "XmOLSooqFJo2"),
	// used to construct the gvproxy admin socket path. The runtime stores box
	// data under the internal ID returned by boxlite_box_id in the C ABI,
	// not the external UUID passed through the runner API. Populated on first
	// EnableSSHAccess and persisted so that DisableSSHAccess and
	// cleanupSSHOnDestroy can resolve the correct socket path without a live
	// box handle.
	InternalBoxID string `json:"internal_box_id,omitempty"`
}

// gvproxyGuestIP is the fixed guest IP inside the gvproxy virtual network.
const gvproxyGuestIP = "192.168.127.2"

// boxSSHMutex returns the per-box mutex for SSH operations, creating it on
// first use. Callers must hold this mutex across the full enable/disable
// critical section to prevent concurrent calls from racing.
func (c *Client) boxSSHMutex(boxId string) *sync.Mutex {
	c.boxSSHMuMu.Lock()
	defer c.boxSSHMuMu.Unlock()
	if m, ok := c.boxSSHMu[boxId]; ok {
		return m
	}
	m := &sync.Mutex{}
	c.boxSSHMu[boxId] = m
	return m
}

// EnableSSHAccess sets up SSH port forwarding and starts sshd in the container.
// Returns the allocated host port.
//
// Idempotency rule: if SSH is already enabled for this box AND the caller sends
// identical authorized_keys and unix_user, the existing port is returned without
// contacting the guest. If either field differs, EnableSSH is re-called in the
// guest so new authorized_keys replace the old set and the stored state is
// updated. This prevents a key-rotation or user-change request from silently
// returning success while the guest keeps stale credentials.
//
// Concurrent Enable calls for the same box are serialised by a per-box mutex
// so that two simultaneous requests cannot double-allocate a port or clobber
// each other's gvproxy rule.
func (c *Client) EnableSSHAccess(ctx context.Context, boxId string, authorizedKeys []string, unixUser string, alloc *sshport.Allocator) (int, error) {
	mu := c.boxSSHMutex(boxId)
	mu.Lock()
	defer mu.Unlock()

	// Check under the per-box lock — if already enabled with identical
	// credentials, verify/restore the gvproxy forward and return the existing
	// port (true idempotence). If credentials differ, fall through so the guest
	// re-applies the new keys.
	//
	// ForwardHealthy is false when ReapplySSHPortForward failed after a restart
	// (gvproxy socket not yet ready). Re-applying here turns an idempotent
	// enable_ssh retry into the recovery mechanism the Start docstring promises:
	// a caller that re-enables with the same credentials gets a working port
	// rather than a silent 200 with an unreachable forward.
	c.mu.RLock()
	state, already := c.sshStates[boxId]
	// Snapshot the fields we need before releasing the lock. ForwardHealthy is
	// also written by ReapplySSHPortForward (which holds both the per-box SSH
	// mutex and c.mu), so reading it outside c.mu would be a data race.
	var forwardHealthy bool
	var hostPort int
	var disablePending bool
	if already {
		forwardHealthy = state.ForwardHealthy
		hostPort = state.HostPort
		disablePending = state.DisablePending
	}
	c.mu.RUnlock()

	// When DisablePending is true, a previous disable removed the gvproxy
	// forward but the guest cleanup did not complete. The caller wants to
	// enable SSH (possibly for a different unix_user). Before falling through
	// to the fresh allocation path we must finish the pending guest cleanup
	// when the user changes — leaving the old user's .ssh_enabled marker and
	// authorized_keys on disk would let restart recovery resurrect sshd with
	// revoked credentials.
	//
	// If the user is the same, the old-user marker was for this user anyway;
	// re-enabling will overwrite it, so no separate DisableSSH call is needed.
	//
	// After this block we fall through to the full allocation path regardless.
	// The stale state (and its allocated port) will be overwritten atomically
	// below; we do not call alloc.Release here because the same port may be
	// re-allocated immediately for this box.
	//
	// disablePendingPort records the port held by the DisablePending state so
	// that the rollback path (EnableSSH failure + successful unexpose) can
	// identify whether alloc.Release will free the same port that sshStates
	// still references. If so, the stale state entry must also be deleted —
	// otherwise GetSSHAccess returns the old HostPort while the allocator is
	// free to hand that same port to a different box (tenant isolation bug).
	var disablePendingPort int
	if disablePending {
		disablePendingPort = state.HostPort
		if state.UnixUser != unixUser {
			// Resolve the box handle so we can issue the guest DisableSSH.
			bxCleanup, _ := c.resolveSSHBox(ctx, boxId)
			if bxCleanup == nil {
				return 0, fmt.Errorf("box %s not reachable for pending disable cleanup of old user %q", boxId, state.UnixUser)
			}
			if err := bxCleanup.DisableSSH(ctx, state.UnixUser); err != nil {
				return 0, fmt.Errorf("disable_ssh (pending old user %q) before user-change failed: %w", state.UnixUser, err)
			}
		}
		already = false
	}

	if already && sshCredentialsMatch(state, authorizedKeys, unixUser) {
		if !forwardHealthy {
			if hostPort == 0 {
				// No host port was allocated when SSH was first enabled (gvproxy was
				// unavailable). There is nothing to restore — fall through to the full
				// allocation path so a proper port and forward can be established now
				// that gvproxy may be available.
				already = false
			} else {
				adminSock := gvproxyAdminSocket(c.homeDir, c.internalBoxID(ctx, boxId, state))
				if err := addGvproxyPortForward(ctx, adminSock, hostPort, 22222); err != nil {
					return 0, fmt.Errorf("ssh port forward for box %s port %d could not be restored: %w", boxId, hostPort, err)
				}
				// Verify the guest sshd is running before marking the forward healthy.
				// The gvproxy rule is now in place, but the guest sshd may have died
				// independently (e.g. after a box restart where EnsureSSH was called by
				// ReapplySSHPortForward and failed). Without this check, ForwardHealthy
				// would be set to true even though every gateway connection would fail —
				// the caller would receive an "enabled" port that is unreachable.
				// This mirrors the same EnsureSSH gate used by ReapplySSHPortForward.
				bx, _ := c.resolveSSHBox(ctx, boxId)
				if bx == nil {
					// Box is not reachable: the gvproxy forward was re-added but the guest
					// sshd cannot be confirmed running. Return an error so the API does NOT
					// save a new token or delete old tokens. The existing degraded state is
					// preserved for retry — the caller can re-enable once the box is running.
					return 0, fmt.Errorf("box %s not reachable, cannot confirm SSH guest sshd is running", boxId)
				}
				if err := bx.EnsureSSH(ctx); err != nil {
					// sshd could not be confirmed or started. Leave ForwardHealthy=false
					// so the next call to GetSSHAccess reports the port as unhealthy and
					// the gateway does not treat a dead sshd as a working connection.
					return 0, fmt.Errorf("ssh guest sshd for box %s could not be verified after forward restore: %w", boxId, err)
				}
				// EnsureSSH succeeded: sshd is confirmed running. Mark the forward healthy.
				c.mu.Lock()
				state.ForwardHealthy = true
				c.mu.Unlock()
			}
		}
		if already {
			return hostPort, nil
		}
	}

	// If SSH is active but credentials are different: re-apply the new keys
	// to the guest using the existing port and gvproxy rule. The port forward
	// is already in place, so we only need to update the guest sshd state and
	// refresh the stored SSHState.
	//
	// Exception: when AuthorizedKeys is nil the state is degraded from a
	// failed initial enable (expose succeeded, EnableSSH failed, rollback
	// unexpose also failed). The gvproxy forward may or may not still be
	// active. Always call addGvproxyPortForward in this path to ensure the
	// forward exists before returning success to the caller.
	if already {
		bx, _ := c.resolveSSHBox(ctx, boxId)
		if bx == nil {
			return 0, fmt.Errorf("box %s not reachable for SSH re-key/user-change", boxId)
		}

		// Degraded initial-enable state: the gvproxy forward may not exist
		// even though we have a stored HostPort. Re-add it before attempting
		// the guest enable so the port is reachable if EnableSSH succeeds.
		// Use the stored HostPort; do not allocate a new one (the port is
		// already reserved in the allocator from the failed first attempt).
		if state.AuthorizedKeys == nil {
			adminSock := gvproxyAdminSocket(c.homeDir, c.internalBoxID(ctx, boxId, state))
			if err := addGvproxyPortForward(ctx, adminSock, state.HostPort, 22222); err != nil {
				return 0, fmt.Errorf("ssh port forward for box %s port %d could not be restored: %w", boxId, state.HostPort, err)
			}
		}

		// When the unix_user changes, revoke the old user's guest-side state
		// before enabling the new user. The guest's enable_ssh does not clean
		// up a previous user's .ssh_enabled marker or authorized_keys; leaving
		// them on disk means restart recovery could resurrect sshd with the
		// old user's credentials. Require the old-user revoke to succeed before
		// proceeding so the caller can retry on transient failure.
		//
		// Skip the revoke when AuthorizedKeys is nil (degraded initial-enable):
		// the guest never had a fully running sshd, so there is no old-user
		// marker to clean up. Attempting DisableSSH in that state is a no-op
		// at best and an unnecessary error surface at worst.
		if state.AuthorizedKeys != nil && state.UnixUser != unixUser {
			if err := bx.DisableSSH(ctx, state.UnixUser); err != nil {
				return 0, fmt.Errorf("disable_ssh (old user %q) before user-change failed: %w", state.UnixUser, err)
			}
		}

		if err := bx.EnableSSH(ctx, authorizedKeys, unixUser); err != nil {
			// The guest killed the old sshd before attempting the replacement.
			// Mark AuthorizedKeys nil so sshCredentialsMatch always returns false
			// on the next call — the next enable will go through the re-key path
			// again rather than hitting the idempotent branch with stale healthy
			// state (which would return the old port without contacting the guest
			// even though sshd is now stopped).
			//
			// ForwardHealthy is set to true (not false) here: the gvproxy port
			// forward is still active and the port is still allocated. Setting it
			// to false causes the runner's GetSSHAccess endpoint to return
			// Enabled=false, which makes the SSH gateway fall back to the exec
			// bridge — routing old tokens through a different identity (sandboxId)
			// and bypassing the unix_user permission boundary that was explicitly
			// configured. Instead, keeping ForwardHealthy=true means the gateway
			// queries the runner, receives Enabled=true, attempts to dial the real-
			// SSH port (which will fail because sshd is stopped), and then rejects
			// the channel (fail-closed, per Round 49 fix). The client sees a clean
			// failure rather than silently degraded access via the exec bridge.
			c.mu.Lock()
			c.sshStates[boxId] = &SSHState{
				HostPort:       state.HostPort,
				UnixUser:       unixUser,
				AuthorizedKeys: nil,                // force re-apply on next call
				ForwardHealthy: true,               // keep forward marked healthy so gateway fails closed
				InternalBoxID:  state.InternalBoxID, // preserve so socket path stays resolvable
			}
			c.mu.Unlock()
			return 0, fmt.Errorf("enable_ssh (re-key) failed: %w", err)
		}
		newState := &SSHState{HostPort: state.HostPort, UnixUser: unixUser, AuthorizedKeys: authorizedKeys, ForwardHealthy: true, InternalBoxID: c.internalBoxID(ctx, boxId, state)}
		c.mu.Lock()
		c.sshStates[boxId] = newState
		c.sshBoxes[boxId] = bx
		c.mu.Unlock()
		// Persist durability contract after re-key:
		//
		// Same-user re-key (key rotation, user unchanged): persist is best-effort.
		// The old and new on-disk states both name the same unixUser. A runner
		// restart loads the stale state but the gateway's unix_user comparison
		// still matches — no routing error occurs. Log the failure and return success.
		//
		// Cross-user re-key (unix_user rotation, user changed): persist is
		// mandatory. If the disk still holds the old unixUser and the runner
		// restarts, reconcileSSHState loads the old user into sshStates. The API
		// has already saved a new token with the new unixUser; the gateway compares
		// new token unixUser vs runner's (old-disk) unixUser → mismatch → token
		// rejected. The caller loses access with no recovery path.
		//
		// Fail hard on persist failure when the user changed so the API does NOT
		// save the new token. The caller receives an error and must retry.
		oldUnixUser := state.UnixUser
		if persistErr := c.persistSSHState(boxId, newState); persistErr != nil {
			if oldUnixUser != unixUser {
				// User changed and disk is not updated: roll back in-memory state to
				// the old user so a caller retry re-enters the re-key path instead of
				// hitting the idempotent branch (which would return success without
				// persisting the new unixUser).
				c.mu.Lock()
				c.sshStates[boxId] = state
				c.mu.Unlock()
				return 0, fmt.Errorf("persist ssh-state after unix_user change failed (in-memory rolled back): %w", persistErr)
			}
			// Same user: safe to leave the old on-disk state; unixUser still matches.
			if c.logger != nil {
				c.logger.WarnContext(ctx, "persist ssh-state after re-key failed (in-memory state is correct, same unix_user)",
					"box", boxId, "error", persistErr)
			}
		}
		return state.HostPort, nil
	}

	// Resolve the SSH-capable box handle. Tests may have pre-populated sshBoxes.
	bx, _ := c.resolveSSHBox(ctx, boxId)
	if bx == nil {
		return 0, fmt.Errorf("box %s not reachable for SSH enable", boxId)
	}

	// Obtain the boxlite-internal short ID (e.g. "XmOLSooqFJo2") so that
	// gvproxyAdminSocket constructs the correct filesystem path. The runtime
	// stores per-box sockets under the internal ID, not the external UUID.
	// getOrFetchBox is cached in c.boxes so this is a map lookup after the
	// first call.
	intID := c.internalBoxID(ctx, boxId, nil)

	hostPort, err := alloc.Allocate(boxId)
	if err != nil {
		return 0, err
	}

	// Attempt to set up the gvproxy port forward (real-SSH mode). When the admin
	// socket is absent (the gvproxy bridge in this deployment does not expose one),
	// log a warning and continue without a port forward. The SSH gateway will use
	// the exec-bridge path in this case; ForwardHealthy is set to false so that
	// GetSSHAccess returns Degraded=true, which the gateway interprets as "fall back
	// to exec-bridge" for tokens whose unix_user matches the exec-bridge user.
	adminSock := gvproxyAdminSocket(c.homeDir, intID)
	forwardEstablished := false
	if fwdErr := addGvproxyPortForward(ctx, adminSock, hostPort, 22222); fwdErr != nil {
		// gvproxy admin socket not available — continue without real-SSH port forward.
		if c.logger != nil {
			c.logger.WarnContext(ctx, "gvproxy port forward not available; SSH gateway will use exec bridge",
				"box", boxId, "port", hostPort, "error", fwdErr)
		}
		// Release the allocated port — it won't be used without a forward.
		if disablePendingPort != 0 && hostPort == disablePendingPort {
			c.mu.Lock()
			delete(c.sshStates, boxId)
			delete(c.sshBoxes, boxId)
			c.mu.Unlock()
		}
		alloc.Release(boxId)
		hostPort = 0
	} else {
		forwardEstablished = true
	}

	if err := bx.EnableSSH(ctx, authorizedKeys, unixUser); err != nil {
		if forwardEstablished {
			// The expose succeeded, so the host port is reachable. Rollback using an
			// independent context so that a canceled or timed-out request context does
			// not silently skip the unexpose and leave 0.0.0.0:hostPort active.
			// Only release the allocator entry when unexpose succeeds; if it fails the
			// port stays allocated so a later (retried) DisableSSHAccess can clean up.
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), gvproxyAdminTimeout)
			unexposeErr := removeGvproxyPortForward(rollbackCtx, adminSock, hostPort)
			rollbackCancel()
			if unexposeErr == nil {
				if disablePendingPort != 0 && hostPort == disablePendingPort {
					c.mu.Lock()
					delete(c.sshStates, boxId)
					delete(c.sshBoxes, boxId)
					c.mu.Unlock()
				}
				alloc.Release(boxId)
			} else {
				// Rollback unexpose failed: store degraded state so DisableSSHAccess
				// or cleanupSSHOnDestroy can retry the unexpose + release.
				c.mu.Lock()
				c.sshStates[boxId] = &SSHState{
					HostPort:       hostPort,
					UnixUser:       unixUser,
					AuthorizedKeys: nil,   // force re-apply; never treated as idempotent match
					ForwardHealthy: false, // sshd not running; forward must be cleaned up
					InternalBoxID:  intID,
				}
				c.sshBoxes[boxId] = bx
				c.mu.Unlock()
			}
		}
		// No forward was established (exec-bridge mode): nothing to roll back on the
		// host side. The guest EnableSSH failed so the user was not created — clean state.
		return 0, fmt.Errorf("enable_ssh failed: %w", err)
	}

	freshState := &SSHState{HostPort: hostPort, UnixUser: unixUser, AuthorizedKeys: authorizedKeys, ForwardHealthy: forwardEstablished, InternalBoxID: intID}
	c.mu.Lock()
	c.sshStates[boxId] = freshState
	c.sshBoxes[boxId] = bx
	c.mu.Unlock()

	// Transactional persist: if the state file cannot be written, roll back.
	// When a gvproxy forward was established (forwardEstablished=true), an
	// un-persisted port would be re-issued to a different box while the old
	// forward (bound to 0.0.0.0:hostPort) may still exist — a tenant isolation
	// violation. When forwardEstablished=false (exec-bridge mode, hostPort=0),
	// there is no host-side exposure to roll back; only the guest DisableSSH is
	// needed to undo the user creation.
	if persistErr := c.persistSSHState(boxId, freshState); persistErr != nil {
		// Roll back guest sshd using an independent context.
		guestCtx, guestCancel := context.WithTimeout(context.Background(), gvproxyAdminTimeout)
		_ = bx.DisableSSH(guestCtx, unixUser)
		guestCancel()

		if forwardEstablished {
			// Roll back the gvproxy forward using an independent context so that a
			// canceled request context doesn't skip the unexpose.
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), gvproxyAdminTimeout)
			unexposeErr := removeGvproxyPortForward(rollbackCtx, adminSock, hostPort)
			rollbackCancel()

			if unexposeErr != nil {
				// Unexpose failed: the forward is still active, so we must NOT
				// release the port back to the allocator.
				degraded := &SSHState{
					HostPort:       hostPort,
					UnixUser:       unixUser,
					AuthorizedKeys: nil,   // force re-apply; not treated as idempotent match
					ForwardHealthy: false, // forward state unknown; persist failed mid-enable
					DisablePending: false, // forward may still be active; retry must unexpose
					InternalBoxID:  intID,
				}
				c.mu.Lock()
				c.sshStates[boxId] = degraded
				c.sshBoxes[boxId] = bx
				c.mu.Unlock()
				_ = c.persistSSHState(boxId, degraded)
				return 0, fmt.Errorf("persist ssh-state failed (%w); gvproxy rollback unexpose also failed: %v — port %d may still be active", persistErr, unexposeErr, hostPort)
			}

			// Unexpose succeeded: the forward is gone. Safe to remove in-memory
			// state and release the port back to the allocator.
			c.mu.Lock()
			delete(c.sshStates, boxId)
			delete(c.sshBoxes, boxId)
			c.mu.Unlock()
			alloc.Release(boxId)
			return 0, fmt.Errorf("persist ssh-state failed: %w; enable rolled back", persistErr)
		}

		// No gvproxy forward to roll back (exec-bridge mode). Clean up in-memory state.
		c.mu.Lock()
		delete(c.sshStates, boxId)
		delete(c.sshBoxes, boxId)
		c.mu.Unlock()
		return 0, fmt.Errorf("persist ssh-state failed: %w; enable rolled back", persistErr)
	}

	return hostPort, nil
}

// DisableSSHAccess stops sshd and removes the port forward.
//
// Security contract: external host-port exposure must be removed regardless of
// whether the in-guest RPC succeeds. A transient guest RPC failure must never
// leave the 0.0.0.0:hostPort forward active with old authorized_keys.
//
// Ordering:
//  1. Guest RPC (stop sshd, remove marker for the correct unix_user). If this
//     fails we record the error but CONTINUE so the host side is always cleaned up.
//  2. Remove the gvproxy port forward (host exposure gone).
//  3. Only when BOTH steps are error-free: commit state removal and release port.
//     If either step failed, state is preserved for a retry and a combined error
//     is returned so the caller knows which step(s) need attention.
func (c *Client) DisableSSHAccess(ctx context.Context, boxId string, alloc *sshport.Allocator) error {
	mu := c.boxSSHMutex(boxId)
	mu.Lock()
	defer mu.Unlock()

	c.mu.RLock()
	state, ok := c.sshStates[boxId]
	c.mu.RUnlock()
	if !ok {
		return nil
	}

	// Fix B: resolve the box handle via sshBoxes cache first, then fall back
	// to getOrFetchBox. This handles the runner-restart case where
	// reconcileSSHState repopulates sshStates but leaves sshBoxes empty.
	// Callers that don't need the guest RPC (bx == nil after fetch) can still
	// proceed with host-side cleanup because the box is not running.
	bx, _ := c.resolveSSHBox(ctx, boxId)

	// Fast-path retry when the gvproxy forward was already removed in a
	// previous attempt (DisablePending=true). Only the guest RPC is outstanding;
	// skip the unexpose to avoid double-calling a rule that no longer exists.
	if state.DisablePending {
		if bx == nil {
			// Box is not reachable (still stopped). The .ssh_enabled marker is still
			// on guest disk — we cannot clean it up until the box starts. Return an
			// error so the caller knows the disable is not yet complete. The state
			// is preserved (DisablePending=true) so ReapplySSHPortForward will
			// attempt the guest cleanup on the next box start.
			if c.logger != nil {
				c.logger.WarnContext(ctx, "box not reachable for SSH disable retry; guest cleanup deferred to next start",
					"box", boxId)
			}
			return fmt.Errorf("disable_ssh retry deferred for %s: box not reachable, guest marker will be removed on next start", boxId)
		}
		if err := bx.DisableSSH(ctx, state.UnixUser); err != nil {
			return fmt.Errorf("disable_ssh rpc retry failed for %s: %w", boxId, err)
		}
		// Guest cleanup done; remove state and release port.
		c.mu.Lock()
		delete(c.sshStates, boxId)
		delete(c.sshBoxes, boxId)
		c.mu.Unlock()
		c.removeSSHStateFile(boxId)
		alloc.Release(boxId)
		return nil
	}

	// Step 1: Guest RPC — stop sshd and remove the restart marker for the
	// unix_user that was stored at enable time. Record failure but do not
	// return early: the host-side forward must be removed regardless so the
	// port is no longer externally reachable.
	var rpcErr error
	if bx == nil {
		// Box not reachable (e.g. stopped after a runner restart). The guest VM
		// is not running, so sshd is also dead — BUT the .ssh_enabled marker and
		// authorized_keys are still on the guest disk. On the next box start the
		// guest init process reads the marker and auto-restarts sshd with the old
		// credentials before any new enable call can clean them up.
		//
		// Treat this as a pending guest failure: rpcErr non-nil will cause the
		// code below to set DisablePending=true and persist the state so that
		// ReapplySSHPortForward (called on the next box Start) can see the pending
		// flag, attempt the guest cleanup, and skip re-adding the forward.
		//
		// The gvproxy unexpose (step 2) still proceeds so the host port is closed
		// immediately. The port and state file are retained until the guest cleanup
		// completes on the next start.
		if c.logger != nil {
			c.logger.WarnContext(ctx, "box not reachable for SSH disable; guest cleanup deferred to next start",
				"box", boxId)
		}
		rpcErr = fmt.Errorf("disable_ssh deferred for %s: box not reachable, guest marker will be removed on next start", boxId)
	} else {
		if err := bx.DisableSSH(ctx, state.UnixUser); err != nil {
			rpcErr = fmt.Errorf("disable_ssh rpc failed for %s: %w", boxId, err)
		}
	}

	// Step 2: Remove host-side gvproxy port forward. Always attempted even
	// when the guest RPC failed above — external exposure must be cleared.
	// Use an independent context so that a canceled or timed-out HTTP request
	// context cannot skip the unexpose and leave 0.0.0.0:hostPort reachable.
	// This mirrors the enable rollback path at addGvproxyPortForward above.
	adminSock := gvproxyAdminSocket(c.homeDir, c.internalBoxID(ctx, boxId, state))
	unexposeCtx, unexposeCancel := context.WithTimeout(context.Background(), gvproxyAdminTimeout)
	unexposeErr := func() error {
		defer unexposeCancel()
		if err := removeGvproxyPortForward(unexposeCtx, adminSock, state.HostPort); err != nil {
			return fmt.Errorf("gvproxy unexpose failed for %s: %w", boxId, err)
		}
		return nil
	}()

	// Step 3: If either cleanup step failed, preserve state for retry and
	// return a combined error. The caller's DELETE handler will surface this.
	if rpcErr != nil || unexposeErr != nil {
		// When the gvproxy unexpose succeeded (host exposure is gone) but the
		// guest RPC failed (sshd marker / authorized_keys not yet removed),
		// mark the state as disable-pending and durably persist it. This prevents
		// ReapplySSHPortForward from silently re-adding the forward on the next
		// box restart, which would undo the successful unexpose and re-expose the
		// port to the host. A subsequent DisableSSHAccess retry will see
		// DisablePending=true and skip the unexpose step, only retrying the guest.
		if rpcErr != nil && unexposeErr == nil {
			c.mu.Lock()
			state.DisablePending = true
			state.ForwardHealthy = false
			c.mu.Unlock()
			// Critical persist: the state file MUST reflect DisablePending=true
			// before we return. In-memory state alone does not survive a runner
			// crash. If the file still holds the pre-disable state
			// (ForwardHealthy=true, DisablePending=false), reconcileSSHState on
			// restart reads it as a healthy state and ReapplySSHPortForward
			// re-adds the gvproxy forward — silently undoing the unexpose that
			// already succeeded and violating the revocation security contract.
			//
			// If persist fails, surface the error alongside rpcErr so the caller
			// knows the partial-disable state is not durable and can retry.
			if persistErr := c.persistSSHState(boxId, state); persistErr != nil {
				if c.logger != nil {
					c.logger.ErrorContext(ctx, "persist ssh-state after partial disable failed — state is not durable; runner restart will re-expose port",
						"box", boxId, "error", persistErr)
				}
				// Combine rpcErr and persistErr so caller sees both failure reasons.
				rpcErr = fmt.Errorf("%w; persist disable-pending state failed: %s", rpcErr, persistErr.Error())
			}
		}
		switch {
		case rpcErr != nil && unexposeErr != nil:
			return fmt.Errorf("%w; %s", rpcErr, unexposeErr.Error())
		case rpcErr != nil:
			return rpcErr
		default:
			return unexposeErr
		}
	}

	// Both steps succeeded — commit state removal and release port.
	c.mu.Lock()
	delete(c.sshStates, boxId)
	delete(c.sshBoxes, boxId)
	c.mu.Unlock()
	c.removeSSHStateFile(boxId)

	alloc.Release(boxId)
	return nil
}

// GetSSHAccess returns a snapshot of the SSH access state for a box.
//
// A value copy is returned (not the internal map pointer) so that callers can
// safely read all fields after the lock is released without racing against
// EnableSSHAccess, DisableSSHAccess, or ReapplySSHPortForward, which mutate
// the same SSHState fields under c.mu.
func (c *Client) GetSSHAccess(boxId string) (SSHState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.sshStates[boxId]
	if !ok {
		return SSHState{}, false
	}
	return *state, true
}

// ReapplySSHPortForward re-adds the gvproxy port forward after a box restart.
// The gvproxy instance is recreated on restart, so port forward rules must be
// re-applied. ctx is used to bound the gvproxy admin call so a stalled socket
// cannot block the Start path indefinitely.
//
// Returns an error when the gvproxy admin call fails. The caller (Start) logs
// the failure but does not propagate it as a Start error — the box is running;
// only the SSH port-forward restoration failed. ForwardHealthy is set to false
// on failure so that a subsequent idempotent enable_ssh call with the same
// credentials will detect the degraded state and re-apply the forward before
// returning success. SSH connections to the stored host port will fail until
// the forward is restored.
//
// Concurrency: this function acquires the same per-box SSH mutex used by
// EnableSSHAccess and DisableSSHAccess so that a concurrent disable cannot
// remove the gvproxy forward and set DisablePending between the state read
// and the addGvproxyPortForward call. Without this mutex a restart-triggered
// reapply could race a DELETE and silently re-expose a port that the caller
// explicitly requested to close.
func (c *Client) ReapplySSHPortForward(ctx context.Context, boxId string) error {
	mu := c.boxSSHMutex(boxId)
	mu.Lock()
	defer mu.Unlock()

	c.mu.RLock()
	state, ok := c.sshStates[boxId]
	c.mu.RUnlock()
	if !ok {
		return nil
	}

	// If a disable was partially completed (guest cleanup failed or was deferred
	// because the box was stopped, but the gvproxy forward was already removed),
	// do not re-add the forward on restart. The caller explicitly requested
	// disable; re-exposing the port would silently undo that intent.
	//
	// When the box is now reachable (it just started), attempt the deferred guest
	// cleanup here: call DisableSSH to remove the .ssh_enabled marker and stop
	// sshd. On success, remove state and release the port — the disable is fully
	// committed. On failure, leave DisablePending=true so a later
	// DisableSSHAccess retry can finish, and still skip the forward re-add.
	if state.DisablePending {
		bx, _ := c.resolveSSHBox(ctx, boxId)
		if bx != nil {
			if err := bx.DisableSSH(ctx, state.UnixUser); err != nil {
				if c.logger != nil {
					c.logger.WarnContext(ctx, "deferred SSH disable guest RPC failed on box start; will retry on next disable call",
						"box", boxId, "error", err)
				}
				// Leave DisablePending=true; do not re-add the forward.
				return nil
			}
			// Guest cleanup succeeded — commit state removal and release port.
			c.mu.Lock()
			delete(c.sshStates, boxId)
			delete(c.sshBoxes, boxId)
			c.mu.Unlock()
			c.removeSSHStateFile(boxId)
			if c.sshAlloc != nil {
				c.sshAlloc.Release(boxId)
			}
			if c.logger != nil {
				c.logger.InfoContext(ctx, "deferred SSH disable guest cleanup completed on box start",
					"box", boxId)
			}
		}
		// Box not yet reachable or guest cleanup succeeded — either way, do not
		// re-add the forward.
		return nil
	}

	// If the state is degraded (AuthorizedKeys == nil), the initial enable call
	// failed: the guest EnableSSH RPC returned an error and the caller never
	// got a successful response. The .ssh_enabled marker may still be on disk
	// from an earlier non-transactional write (pre-fix guest), which means the
	// guest sshd could auto-restart from it on box restart. Re-adding the gvproxy
	// forward here would expose that stale sshd instance to the host even though
	// the API reported the enable as failed. Skip the forward; a subsequent
	// successful EnableSSHAccess call will re-add it as part of its own flow.
	if state.AuthorizedKeys == nil {
		return nil
	}

	adminSock := gvproxyAdminSocket(c.homeDir, c.internalBoxID(ctx, boxId, state))
	if err := addGvproxyPortForward(ctx, adminSock, state.HostPort, 22222); err != nil {
		// Mark the forward as unhealthy so the next idempotent enable_ssh
		// call re-applies it instead of returning a silent success with a
		// broken port.
		c.mu.Lock()
		state.ForwardHealthy = false
		c.mu.Unlock()
		return fmt.Errorf("reapply ssh port forward for box %s port %d: %w", boxId, state.HostPort, err)
	}

	// The gvproxy rule is in place, but the guest sshd may not be running
	// (e.g. the box was stopped and restarted, killing the sshd process).
	// Verify the guest listener is up before marking the forward as healthy.
	// Only set ForwardHealthy=true when EnsureSSH confirms sshd is running;
	// otherwise, leave it false so the next idempotent EnableSSHAccess call
	// will detect the degraded state and re-apply the forward rather than
	// returning a silent 200 with an unreachable port.
	bx, _ := c.resolveSSHBox(ctx, boxId)
	if bx != nil {
		if err := bx.EnsureSSH(ctx); err != nil {
			if c.logger != nil {
				c.logger.WarnContext(ctx, "reapply ssh port forward: guest sshd not running and could not be started; port forward is active but unreachable",
					"box", boxId, "port", state.HostPort, "error", err)
			}
			// Leave ForwardHealthy=false: the gvproxy rule is active but
			// sshd is not running. The next idempotent EnableSSHAccess call
			// with the same credentials will re-apply the forward (which is
			// already in place) and retry the guest enable.
			c.mu.Lock()
			state.ForwardHealthy = false
			c.mu.Unlock()
			return nil
		}
	}
	// Either the box is not reachable yet (will be retried on next EnableSSH)
	// or EnsureSSH confirmed sshd is listening. Mark forward as healthy only
	// when the guest was reachable and confirmed running.
	c.mu.Lock()
	if bx != nil {
		state.ForwardHealthy = true
	} else {
		// Box not yet reachable after restart (e.g. still booting). Leave
		// ForwardHealthy=false — the next EnableSSH call will restore it.
		state.ForwardHealthy = false
	}
	c.mu.Unlock()
	return nil
}

// cleanupSSHOnDestroy releases SSH port and state for a box that is being
// destroyed. The VM is already gone so we skip the guest RPC and only clean
// up host-side resources. alloc may be nil (no-op Release).
//
// This is called from Destroy to prevent port pool exhaustion on repeated
// enable+destroy cycles without an explicit Disable.
func (c *Client) cleanupSSHOnDestroy(ctx context.Context, boxId string, alloc *sshport.Allocator) {
	mu := c.boxSSHMutex(boxId)
	mu.Lock()
	defer mu.Unlock()

	c.mu.RLock()
	state, ok := c.sshStates[boxId]
	c.mu.RUnlock()
	if !ok {
		return
	}

	// Best-effort unexpose; the VM is gone so the port forward is already
	// dead, but clean up gvproxy state if the admin socket is still present.
	adminSock := gvproxyAdminSocket(c.homeDir, c.internalBoxID(ctx, boxId, state))
	_ = removeGvproxyPortForward(ctx, adminSock, state.HostPort)

	c.mu.Lock()
	delete(c.sshStates, boxId)
	delete(c.sshBoxes, boxId)
	c.mu.Unlock()
	c.removeSSHStateFile(boxId)

	if alloc != nil {
		alloc.Release(boxId)
	}
}

// sshStatePath returns the path of the on-disk SSH state file for a box.
// The file lives alongside other per-box data so it is removed automatically
// when the box directory is cleaned up by the runtime.
func (c *Client) sshStatePath(boxId string) string {
	return filepath.Join(c.homeDir, "boxes", boxId, "ssh-state.json")
}

// persistSSHState writes the current SSH state for boxId to disk so that a
// runner restart can recover the allocation without losing track of in-use ports.
// Returns an error when the write fails so that callers in the critical enable
// path can roll back rather than leaving an undurable allocation in place.
func (c *Client) persistSSHState(boxId string, state *SSHState) error {
	data, err := json.Marshal(state)
	if err != nil {
		// SSHState contains only plain types; Marshal should never fail.
		return err
	}
	path := c.sshStatePath(boxId)
	// MkdirAll is idempotent; the boxes/<boxId> dir typically already exists.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for ssh-state.json: %w", err)
	}
	// Write to a temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write ssh-state.json tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename ssh-state.json: %w", err)
	}
	return nil
}

// removeSSHStateFile deletes the on-disk SSH state file for boxId.
// Errors (including NotFound) are silently ignored — the file is best-effort
// and callers handle the removal as part of box cleanup.
func (c *Client) removeSSHStateFile(boxId string) {
	_ = os.Remove(c.sshStatePath(boxId))
}

// reconcileSSHState walks the boxes directory, loads any persisted ssh-state.json
// files, reserves their ports in the allocator, and rebuilds the in-memory
// sshStates map. Called once at the end of NewClient so that a runner restart
// does not lose track of ports that are still allocated in gvproxy.
//
// Errors during directory walking are skipped — a partially-recovered state is
// better than aborting startup entirely.
//
// Corrupt or unreadable state files: if the file exists but cannot be parsed,
// reconcileSSHState attempts a best-effort extraction of HostPort from the raw
// bytes. When a port is identified, it is reserved under a sentinel boxId
// ("__corrupt__:<boxId>") so the allocator cannot hand that port to a different
// box while the old gvproxy forward may still be active. The sshStates map is
// NOT populated for corrupt entries — no normal SSH operation will succeed for
// them. The quarantined port will be freed only when the state file is removed
// or corrected (e.g. after the box is destroyed and recreated).
func (c *Client) reconcileSSHState(alloc *sshport.Allocator) {
	if alloc == nil {
		return
	}
	boxesDir := filepath.Join(c.homeDir, "boxes")
	entries, err := os.ReadDir(boxesDir)
	if err != nil {
		// boxes/ may not exist on a freshly provisioned host — that is fine.
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		boxId := entry.Name()
		stateFile := filepath.Join(boxesDir, boxId, "ssh-state.json")
		data, err := os.ReadFile(stateFile)
		if err != nil {
			continue // no state file or unreadable without known port — skip
		}
		var state SSHState
		if err := json.Unmarshal(data, &state); err != nil {
			// Corrupt state file: attempt best-effort port extraction so the
			// allocator can quarantine the port and prevent reuse while the
			// old gvproxy forward may still be active.
			if port := extractHostPortFromCorruptJSON(data); port > 0 {
				sentinelId := "__corrupt__:" + boxId
				if reserveErr := alloc.ReservePort(sentinelId, port); reserveErr == nil {
					if c.logger != nil {
						c.logger.Warn("corrupt ssh-state.json: port quarantined to prevent reuse",
							"box", boxId, "port", port)
					}
				}
			} else if c.logger != nil {
				c.logger.Warn("corrupt ssh-state.json: cannot extract port; skipping quarantine",
					"box", boxId)
			}
			continue
		}
		if state.HostPort == 0 {
			// Exec-bridge mode: no port was allocated (gvproxy not available when
			// SSH was enabled). Restore the in-memory state so GetSSHAccess returns
			// Degraded=true, which causes the SSH gateway to fall back to exec-bridge
			// rather than treating the box as "SSH never configured".
			// Skip ReservePort — there is no host port to reserve.
			if state.UnixUser == "" {
				continue // genuinely empty / corrupt entry
			}
			c.mu.Lock()
			c.sshStates[boxId] = &state
			c.mu.Unlock()
			continue
		}
		if err := alloc.ReservePort(boxId, state.HostPort); err != nil {
			// Port already taken by another box (should not happen in practice)
			// or out of range — skip this entry to avoid double-allocation.
			continue
		}
		c.mu.Lock()
		c.sshStates[boxId] = &state
		c.mu.Unlock()
	}
}

// extractHostPortFromCorruptJSON attempts to read the "HostPort" integer value
// from raw bytes that could not be fully parsed as JSON. It uses a lenient
// decoder that stops at the first error rather than requiring the whole document
// to be well-formed. Returns 0 if the field is absent or cannot be read.
func extractHostPortFromCorruptJSON(data []byte) int {
	// json.Decoder reads tokens one at a time and can extract fields from a
	// truncated document — it returns an error only when it actually encounters
	// a malformed token, not on EOF mid-document.
	dec := json.NewDecoder(bytes.NewReader(data))
	// Consume the opening '{'.
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return 0
	}
	for dec.More() {
		// Read the field name.
		keyTok, err := dec.Token()
		if err != nil {
			break
		}
		key, ok := keyTok.(string)
		if !ok {
			break
		}
		// Read the field value.
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			break
		}
		if key == "HostPort" {
			var port int
			if err := json.Unmarshal(val, &port); err == nil {
				return port
			}
		}
	}
	return 0
}

// gvproxyAdminTimeout is the maximum time allowed for a single gvproxy admin
// call (expose or unexpose). The admin socket is a local Unix socket; 10 s is
// generous enough for any healthy gvproxy instance and short enough to bound
// how long the per-box SSH mutex can be held by a stalled I/O call.
const gvproxyAdminTimeout = 10 * time.Second

// internalBoxID returns the boxlite-internal short ID (e.g. "XmOLSooqFJo2")
// for a box, used to construct filesystem paths such as the gvproxy admin
// socket. The runtime stores per-box data under the internal ID returned by
// boxlite_box_id in the C ABI, not the external UUID exposed through the
// runner API.
//
// Resolution order:
//  1. state.InternalBoxID — cheapest; populated on first EnableSSHAccess.
//  2. getOrFetchBox → bx.ID() — resolves via the runtime (result cached).
//  3. boxId fallback — returns the external UUID, which gives the wrong
//     filesystem path but is safe for destruction paths where the socket is
//     already gone. Also used in unit tests where c.runtime is nil.
func (c *Client) internalBoxID(ctx context.Context, boxId string, state *SSHState) string {
	if state != nil && state.InternalBoxID != "" {
		return state.InternalBoxID
	}
	if c.runtime != nil {
		sdkBox, _ := c.getOrFetchBox(ctx, boxId)
		if sdkBox != nil {
			return sdkBox.ID()
		}
	}
	return boxId
}

// gvproxyAdminSocket returns the path to the gvproxy HTTP admin Unix socket for a box.
func gvproxyAdminSocket(homeDir, boxId string) string {
	return filepath.Join(homeDir, "boxes", boxId, "sockets", "gvproxy-admin.sock")
}

// gvproxyHTTPClient returns an http.Client that sends requests over a Unix
// socket with a bounded overall timeout. The Timeout covers the full
// request/response cycle so a stalled gvproxy admin socket cannot block the
// caller (and its held per-box SSH mutex) indefinitely.
func gvproxyHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: gvproxyAdminTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
			// ResponseHeaderTimeout guards against a server that accepts the
			// connection but never sends response headers.
			ResponseHeaderTimeout: gvproxyAdminTimeout,
		},
	}
}

// resolveSSHBox returns the sshCapable handle for boxId by first checking the
// sshBoxes cache. If the handle is absent (e.g. after a runner restart where
// reconcileSSHState repopulates sshStates but not sshBoxes), it falls back to
// sshBoxFetcher (test hook) and then to getOrFetchBox (production path).
//
// sshBoxFetcher is an injectable hook used by tests to supply a fake sshCapable
// without a real VM runtime. In production, when sshBoxes is empty and no
// fetcher is configured, getOrFetchBox is used to retrieve the box from the
// runtime and wrap it in a boxSSHAdapter.
//
// Returns (nil, nil) when the box cannot be found or is not running.
// Callers should treat nil as "guest unreachable; skip guest RPC."
func (c *Client) resolveSSHBox(ctx context.Context, boxId string) (sshCapable, error) {
	c.mu.RLock()
	bx := c.sshBoxes[boxId]
	c.mu.RUnlock()
	if bx != nil {
		return bx, nil
	}

	// Test hook: use the injected fetcher when set.
	if c.sshBoxFetcher != nil {
		fetched, err := c.sshBoxFetcher(ctx, boxId)
		if err != nil {
			return nil, nil //nolint:nilerr // fetcher error = box not running
		}
		if fetched != nil {
			// Cache so subsequent calls within this operation don't re-fetch.
			c.mu.Lock()
			c.sshBoxes[boxId] = fetched
			c.mu.Unlock()
		}
		return fetched, nil
	}

	// Production path: resolve the box via the real runtime and wrap it in an
	// adapter that implements sshCapable via bx.Exec. This handles the first-time
	// enable (sshBoxes empty) and the runner-restart case (sshStates restored from
	// disk but sshBoxes cleared). getOrFetchBox returns an error when the box does
	// not exist in the runtime; treat that as "not running" rather than propagating.
	sdkBox, err := c.getOrFetchBox(ctx, boxId)
	if err != nil {
		// Box not found in runtime (destroyed, not yet created, or not running).
		// Return nil so callers skip the guest RPC and proceed with host-side
		// cleanup only. Do not propagate the error — this is an expected state
		// after a runner restart if the VM is stopped.
		return nil, nil //nolint:nilerr // box not in runtime = treat as unreachable
	}
	adapter := &boxSSHAdapter{box: sdkBox}
	// Cache the resolved adapter so subsequent resolveSSHBox calls within the
	// same enable/disable critical section (e.g. DisablePending user-change
	// path that calls resolveSSHBox twice) reuse the same handle.
	c.mu.Lock()
	c.sshBoxes[boxId] = adapter
	c.mu.Unlock()
	return adapter, nil
}

// boxSSHAdapter wraps *boxlitesdk.Box to implement sshCapable. It uses the
// Go SDK's Exec path to call the guest-side enable_ssh / disable_ssh / ensure_ssh
// scripts via the BoxLite portal. This avoids requiring native FFI symbols for
// SSH-specific operations that are not yet part of the stable C ABI surface.
type boxSSHAdapter struct {
	box *boxlitesdk.Box
}

// EnableSSH implements sshCapable. It sets up authorized_keys for unixUser and
// starts sshd inside the guest by executing the platform's enable_ssh script.
// The authorized_keys are written as a newline-joined string via shell stdin.
func (a *boxSSHAdapter) EnableSSH(ctx context.Context, authorizedKeys []string, unixUser string) error {
	keysJoined := strings.Join(authorizedKeys, "\n")
	// Pass keys via printf to avoid shell quoting issues with arbitrary key material.
	cmd := fmt.Sprintf(
		"printf '%%s\\n' %s | /usr/local/bin/boxlite-enable-ssh %s",
		shellQuote(keysJoined), shellQuote(unixUser),
	)
	result, err := a.box.Exec(ctx, "/bin/sh", "-c", cmd)
	if err != nil {
		return fmt.Errorf("enable_ssh exec failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("enable_ssh script exited %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

// DisableSSH implements sshCapable. It stops sshd and removes the .ssh_enabled
// marker for unixUser inside the guest by executing the platform's disable_ssh script.
func (a *boxSSHAdapter) DisableSSH(ctx context.Context, unixUser string) error {
	result, err := a.box.Exec(ctx, "/usr/local/bin/boxlite-disable-ssh", unixUser)
	if err != nil {
		return fmt.Errorf("disable_ssh exec failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("disable_ssh script exited %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

// EnsureSSH implements sshCapable. It verifies sshd is listening on :22222
// inside the guest and starts it if not, by executing the platform's
// ensure_ssh script. Called by ReapplySSHPortForward after a box restart so
// ForwardHealthy is only marked true when the guest listener is confirmed.
func (a *boxSSHAdapter) EnsureSSH(ctx context.Context) error {
	result, err := a.box.Exec(ctx, "/usr/local/bin/boxlite-ensure-ssh")
	if err != nil {
		return fmt.Errorf("ensure_ssh exec failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("ensure_ssh script exited %d: %s", result.ExitCode, result.Stderr)
	}
	return nil
}

// shellQuote wraps s in single quotes so it is safe to pass as a shell argument.
// Single quotes inside s are escaped as '\'' (end quote, literal quote, reopen quote).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// sshCredentialsMatch reports whether the stored SSHState represents the same
// set of credentials as the incoming request. Used by EnableSSHAccess to decide
// whether a re-enable is a true no-op (same keys + user) or a rotation that
// requires re-applying the new credentials to the guest.
func sshCredentialsMatch(state *SSHState, authorizedKeys []string, unixUser string) bool {
	if state.UnixUser != unixUser {
		return false
	}
	if len(state.AuthorizedKeys) != len(authorizedKeys) {
		return false
	}
	for i, k := range authorizedKeys {
		if state.AuthorizedKeys[i] != k {
			return false
		}
	}
	return true
}

// addGvproxyPortForward sends an expose request to the gvproxy admin socket.
// ctx is honoured for cancellation; the http.Client also carries an absolute
// deadline (gvproxyAdminTimeout) so the call cannot block indefinitely.
//
// Security note: the "local" address is intentionally 0.0.0.0 (all interfaces).
// Restricting the bind to 127.0.0.1 would prevent the SSH gateway (running on
// a separate host) from reaching the VM sshd. Two independent controls make
// direct bypass impossible:
//
//  1. Guest authorized_keys contains ONLY the gateway's public key — not any
//     caller-supplied key. A direct TCP connection to the host port cannot
//     authenticate to guest sshd without the gateway's private key, which callers
//     never possess.
//
//  2. AWS security group restricts the SSH port range (22100-22199) to allow
//     inbound traffic only from the SSH gateway's security group, so packets from
//     arbitrary IPs never reach the port at the network layer.
//
// Both controls must be satisfied simultaneously: (1) ensures auth fails even if
// an attacker somehow reaches the port, and (2) ensures the port is unreachable
// from outside the gateway SG even if a key were somehow leaked. The gateway
// validates the caller's token before proxying, so the full chain is:
// valid token → gateway SG network path → gateway private key → guest sshd.
func addGvproxyPortForward(ctx context.Context, adminSock string, hostPort, guestPort int) error {
	client := gvproxyHTTPClient(adminSock)
	body := fmt.Sprintf(`{"local":"0.0.0.0:%d","remote":"%s:%d","protocol":"tcp"}`,
		hostPort, gvproxyGuestIP, guestPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://gvproxy/services/forwarder/expose", bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gvproxy expose returned %d", resp.StatusCode)
	}
	return nil
}

// removeGvproxyPortForward sends an unexpose request to the gvproxy admin socket.
// ctx is honoured for cancellation; the http.Client also carries an absolute
// deadline (gvproxyAdminTimeout) so the call cannot block indefinitely.
func removeGvproxyPortForward(ctx context.Context, adminSock string, hostPort int) error {
	client := gvproxyHTTPClient(adminSock)
	body := fmt.Sprintf(`{"local":"0.0.0.0:%d","protocol":"tcp"}`, hostPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://gvproxy/services/forwarder/unexpose", bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gvproxy unexpose returned %d", resp.StatusCode)
	}
	return nil
}
