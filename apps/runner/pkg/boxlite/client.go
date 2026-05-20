// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024 BoxLite AI (originally Daytona Platforms Inc.
// Modified and rebranded for BoxLite

// Package boxlite provides a BoxLite-backed implementation of the sandbox runtime,
// replacing Docker with VM-based isolation via the BoxLite Go SDK.
package boxlite

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	boxlite "github.com/boxlite-ai/boxlite/sdks/go"
	"github.com/boxlite-ai/runner/pkg/api/dto"
	"github.com/boxlite-ai/runner/pkg/models/enums"
	"github.com/boxlite-ai/runner/pkg/sshport"
	"github.com/containerd/errdefs"
)

// Client wraps the BoxLite Go SDK to provide the same interface as the Docker client.
// It manages VMs instead of containers, providing hardware-level isolation.
type Client struct {
	runtime            *boxlite.Runtime
	logger             *slog.Logger
	insecureRegistries []string
	mu                 sync.RWMutex
	boxes              map[string]*boxlite.Box
	// homeDir is the BoxLite home directory (absolute path). Stored here so that
	// SSH helpers (gvproxyAdminSocket, sshStatePath) can compute per-box paths
	// without re-resolving the home directory on each call.
	homeDir            string
	// sshStates holds runtime SSH access state for each box that has (or had)
	// SSH enabled. Guarded by mu. Populated by EnableSSHAccess; cleared by
	// DisableSSHAccess and cleanupSSHOnDestroy.
	sshStates          map[string]*SSHState
	// sshBoxes holds the sshCapable handle for each box that has (or had)
	// SSH enabled. Populated by EnableSSHAccess; cleared by disable/destroy.
	// Tests may pre-populate this map with stubs to avoid a real VM runtime.
	sshBoxes           map[string]sshCapable
	// sshBoxFetcher is an optional hook used by tests to inject a fake sshCapable
	// without requiring a real BoxLite runtime. When nil (production), resolveSSHBox
	// falls back to getOrFetchBox. Tests set this field to control box resolution.
	sshBoxFetcher      func(ctx context.Context, boxId string) (sshCapable, error)
	// sshAlloc is the port allocator shared with the SSH controller.
	// Stored here so Destroy can release the port without changing its signature.
	sshAlloc           *sshport.Allocator
	// boxSSHMu serialises concurrent Enable/Disable calls per box so that
	// two simultaneous POST /ssh-access requests cannot double-allocate a port.
	boxSSHMuMu         sync.Mutex
	boxSSHMu           map[string]*sync.Mutex
	awsRegion          string
	awsEndpointUrl     string
	awsAccessKeyId     string
	awsSecretAccessKey string
	volumeMutexes      map[string]*sync.Mutex
	volumeMutexesMutex sync.Mutex
	volumeCleanupMutex sync.Mutex
	lastVolumeCleanup  time.Time
	volumeCleanup      volumeCleanupConfig
}

// ClientConfig holds configuration for the BoxLite client.
type ClientConfig struct {
	Logger                       *slog.Logger
	HomeDir                      string
	InsecureRegistries           []string
	AWSRegion                    string
	AWSEndpointUrl               string
	AWSAccessKeyId               string
	AWSSecretAccessKey           string
	VolumeCleanupInterval        time.Duration
	VolumeCleanupDryRun          bool
	VolumeCleanupExclusionPeriod time.Duration
	// SSHPortAllocator is the allocator used by the SSH controller. When set,
	// Destroy automatically releases the SSH port so the pool is not exhausted
	// by repeated enable+destroy cycles without an explicit Disable.
	SSHPortAllocator *sshport.Allocator
}

// resolveBoxliteHomeDir returns an absolute BoxLite home directory path.
//
// When dir is non-empty it is returned unchanged (caller's explicit choice).
// Otherwise the function mirrors the Rust runtime's default_home_dir logic:
// use $BOXLITE_HOME if set, else $HOME/.boxlite.
// An empty return value is only possible if $HOME is also unset.
func resolveBoxliteHomeDir(dir string) string {
	if dir != "" {
		return dir
	}
	if env := os.Getenv("BOXLITE_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".boxlite")
}

func networkSpec(blockAll *bool, allowList *string) boxlite.NetworkSpec {
	if blockAll != nil && *blockAll {
		return boxlite.NetworkSpec{Mode: boxlite.NetworkModeDisabled}
	}

	spec := boxlite.NetworkSpec{Mode: boxlite.NetworkModeEnabled}
	if allowList == nil {
		return spec
	}

	for _, entry := range strings.Split(*allowList, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			spec.AllowNet = append(spec.AllowNet, entry)
		}
	}
	return spec
}

// NewClient creates a new BoxLite client backed by the BoxLite VM runtime.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	resolvedHomeDir := resolveBoxliteHomeDir(config.HomeDir)
	var opts []boxlite.RuntimeOption
	if resolvedHomeDir != "" {
		opts = append(opts, boxlite.WithHomeDir(resolvedHomeDir))
	}
	insecureRegistries := normalizeRegistryHosts(config.InsecureRegistries)
	if len(insecureRegistries) > 0 {
		registries := make([]boxlite.ImageRegistry, 0, len(insecureRegistries))
		for _, host := range insecureRegistries {
			registries = append(registries, boxlite.ImageRegistry{
				Host:       host,
				Transport:  boxlite.RegistryTransportHTTP,
				SkipVerify: true,
			})
		}
		opts = append(opts, boxlite.WithImageRegistries(registries...))
	}

	rt, err := boxlite.NewRuntime(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create boxlite runtime: %w", err)
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	c := &Client{
		runtime:            rt,
		logger:             logger,
		insecureRegistries: insecureRegistries,
		boxes:              make(map[string]*boxlite.Box),
		homeDir:            resolvedHomeDir,
		sshStates:          make(map[string]*SSHState),
		sshBoxes:           make(map[string]sshCapable),
		boxSSHMu:           make(map[string]*sync.Mutex),
		sshAlloc:           config.SSHPortAllocator,
		awsRegion:          config.AWSRegion,
		awsEndpointUrl:     config.AWSEndpointUrl,
		awsAccessKeyId:     config.AWSAccessKeyId,
		awsSecretAccessKey: config.AWSSecretAccessKey,
		volumeMutexes:      make(map[string]*sync.Mutex),
		volumeCleanup: volumeCleanupConfig{
			interval:        config.VolumeCleanupInterval,
			dryRun:          config.VolumeCleanupDryRun,
			exclusionPeriod: config.VolumeCleanupExclusionPeriod,
		},
	}

	// Recover SSH state from disk so a runner restart does not lose track of
	// ports that are still allocated in gvproxy. Must be called after c is
	// fully initialised so reconcileSSHState can populate c.sshStates and the
	// allocator can reserve the ports.
	c.reconcileSSHState(config.SSHPortAllocator)

	return c, nil
}

// Shutdown gracefully stops all running boxes in the underlying BoxLite
// runtime. Blocks until shutdown completes or `timeout` elapses. Call this
// BEFORE Close so VMs aren't killed mid-write on systemd SIGTERM.
//
// Without this, restart attempts for the killed boxes hit a 30s
// `guest_connect` timeout because the guest agent inside never re-establishes
// vsock after an unclean shutdown — and (until the matching Rust-side fix
// landed) that timeout would auto-delete the box record.
//
// `timeout=0` means "use the runtime default (10s)". Negative values are
// clamped by the SDK.
func (c *Client) Shutdown(ctx context.Context, timeout time.Duration) error {
	return c.runtime.Shutdown(ctx, timeout)
}

// Close releases the BoxLite runtime handle. Prefer calling `Shutdown` first
// so boxes get a graceful stop before the C handle is freed.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, bx := range c.boxes {
		bx.Close()
		delete(c.boxes, id)
	}
	return c.runtime.Close()
}

// Create creates a new sandbox (VM) from the given image and configuration.
// Returns the box ID and daemon version.
func (c *Client) Create(ctx context.Context, sandboxDto dto.CreateSandboxDTO) (string, string, error) {
	// API sends cores / GB / GB as small integers (see apps/api Sandbox entity).
	cpus := int(sandboxDto.CpuQuota)
	if cpus < 1 {
		cpus = 1
	}
	memoryMiB := int(sandboxDto.MemoryQuota * 1024)
	if memoryMiB < 128 {
		memoryMiB = 128
	}
	opts := []boxlite.BoxOption{
		boxlite.WithName(sandboxDto.Id),
		boxlite.WithCPUs(cpus),
		boxlite.WithMemory(memoryMiB),
		boxlite.WithAutoRemove(false),
		boxlite.WithDetach(true),
	}
	if sandboxDto.StorageQuota > 0 {
		opts = append(opts, boxlite.WithDiskSize(int(sandboxDto.StorageQuota)))
	}

	for k, v := range sandboxDto.Env {
		opts = append(opts, boxlite.WithEnv(k, v))
	}

	if len(sandboxDto.Entrypoint) > 0 {
		opts = append(opts, boxlite.WithEntrypoint(sandboxDto.Entrypoint...))
	}

	volumeMounts, err := c.getVolumeMounts(ctx, sandboxDto.Volumes)
	if err != nil {
		return "", "", err
	}
	for _, vol := range volumeMounts {
		opts = append(opts, boxlite.WithVolume(vol.hostPath, vol.mountPath))
	}

	if len(volumeMounts) > 0 {
		if err := c.recordSandboxVolumeMounts(ctx, sandboxDto.Id, volumeMounts); err != nil {
			return "", "", err
		}
	}

	opts = append(opts, boxlite.WithNetwork(networkSpec(sandboxDto.NetworkBlockAll, sandboxDto.NetworkAllowList)))

	bx, err := c.runtime.Create(ctx, sandboxDto.Snapshot, opts...)
	if err != nil {
		if len(volumeMounts) > 0 {
			if cleanupErr := c.removeSandboxVolumeMountRecord(ctx, sandboxDto.Id); cleanupErr != nil {
				c.logger.WarnContext(ctx, "failed to remove sandbox volume mount record after create failure", "sandbox", sandboxDto.Id, "error", cleanupErr)
			}
		}
		return "", "", fmt.Errorf("failed to create box: %w", err)
	}

	c.mu.Lock()
	c.boxes[sandboxDto.Id] = bx
	c.mu.Unlock()

	c.logger.Info("created box", "id", bx.ID(), "name", bx.Name(), "image", sandboxDto.Snapshot)

	skipStart := sandboxDto.SkipStart != nil && *sandboxDto.SkipStart
	if !skipStart {
		if err := bx.Start(ctx); err != nil {
			return bx.ID(), "", fmt.Errorf("failed to start box: %w", err)
		}
	}

	return bx.ID(), "boxlite", nil
}

// Start starts a stopped sandbox and returns the daemon version.
func (c *Client) Start(ctx context.Context, sandboxId string, authToken *string, metadata map[string]string) (string, error) {
	if err := c.ensureVolumeMountsFromMetadata(ctx, sandboxId, metadata); err != nil {
		c.logger.ErrorContext(ctx, "failed to ensure volume FUSE mounts", "error", err)
	}

	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return "", err
	}
	if err := bx.Start(ctx); err != nil {
		return "", err
	}

	// Re-add the gvproxy port forward for any SSH-enabled sandbox after restart.
	// The gvproxy instance is recreated on box start, so the port forward rules
	// must be re-applied. ForwardHealthy is set to false on failure so that a
	// subsequent idempotent enable_ssh call detects and re-applies the forward.
	if err := c.ReapplySSHPortForward(ctx, sandboxId); err != nil {
		c.logger.WarnContext(ctx, "failed to reapply SSH port forward after start; SSH port forward will be unavailable until next enable_ssh call",
			"sandbox", sandboxId, "error", err)
	}

	return "boxlite", nil
}

// Stop stops a running sandbox.
func (c *Client) Stop(ctx context.Context, sandboxId string, force bool) error {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return err
	}
	err = bx.Stop(ctx)

	c.mu.Lock()
	delete(c.boxes, sandboxId)
	c.mu.Unlock()

	return err
}

// Destroy removes a sandbox entirely.
func (c *Client) Destroy(ctx context.Context, sandboxId string) error {
	c.mu.Lock()
	if bx, ok := c.boxes[sandboxId]; ok {
		bx.Close()
		delete(c.boxes, sandboxId)
	}
	c.mu.Unlock()

	if err := c.runtime.ForceRemove(ctx, sandboxId); err != nil {
		return err
	}

	// Release any SSH port held by this sandbox. The VM is now gone so only
	// host-side cleanup is needed (no guest RPC). alloc may be nil (no-op).
	c.cleanupSSHOnDestroy(ctx, sandboxId, c.sshAlloc)

	if err := c.removeSandboxVolumeMountRecord(ctx, sandboxId); err != nil {
		c.logger.WarnContext(ctx, "failed to remove sandbox volume mount record", "sandbox", sandboxId, "error", err)
	}
	c.CleanupOrphanedVolumeMounts(ctx)

	return nil
}

// GetSandboxState returns the current state of a sandbox.
func (c *Client) GetSandboxState(ctx context.Context, sandboxId string) (enums.SandboxState, error) {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		if boxlite.IsNotFound(err) {
			return enums.SandboxStateUnknown, nil
		}
		return enums.SandboxStateUnknown, err
	}

	info, err := bx.Info(ctx)
	if err != nil {
		return enums.SandboxStateUnknown, err
	}

	switch info.State {
	case boxlite.StateRunning:
		return enums.SandboxStateStarted, nil
	case boxlite.StateStopped:
		return enums.SandboxStateStopped, nil
	case boxlite.StateConfigured:
		return enums.SandboxStateCreating, nil
	default:
		return enums.SandboxStateUnknown, nil
	}
}

// StartExecution starts an interactive execution in a sandbox.
// env is merged into the process environment; nil or empty inherits the
// container default (same semantics as ExecutionOptions.Env in the SDK).
// user is the OS user inside the guest (e.g., "boxlite"); empty inherits the
// container image default.
// onExit, if non-nil, is called after the last stdout/stderr byte for this
// execution has been delivered — callers that must not close stdout/stderr
// writers until all output is drained should use this as their drain signal.
func (c *Client) StartExecution(ctx context.Context, sandboxId string, command string, args []string, stdout, stderr io.Writer, tty bool, env map[string]string, user string, onExit func(int)) (*boxlite.Execution, error) {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return nil, err
	}
	return bx.StartExecution(ctx, command, args, &boxlite.ExecutionOptions{
		TTY:    tty,
		Stdout: stdout,
		Stderr: stderr,
		Env:    env,
		User:   user,
		OnExit: onExit,
	})
}

// Exec executes a command in a running sandbox and returns the result.
func (c *Client) Exec(ctx context.Context, sandboxId string, command string, args ...string) (*ExecResult, error) {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return nil, err
	}

	result, err := bx.Exec(ctx, command, args...)
	if err != nil {
		return nil, err
	}

	return &ExecResult{
		StdOut:   result.Stdout,
		StdErr:   result.Stderr,
		ExitCode: result.ExitCode,
	}, nil
}

// CopyInto copies a file from host into a sandbox.
func (c *Client) CopyInto(ctx context.Context, sandboxId string, hostSrc, guestDst string) error {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return err
	}
	return bx.CopyInto(ctx, hostSrc, guestDst)
}

// CopyOut copies a file from a sandbox to the host.
func (c *Client) CopyOut(ctx context.Context, sandboxId string, guestSrc, hostDst string) error {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return err
	}
	return bx.CopyOut(ctx, guestSrc, hostDst)
}

// PullImage pulls an OCI image into the runtime's cache.
func (c *Client) PullImage(ctx context.Context, imageName string) error {
	c.logger.Info("pulling image", "image", imageName)
	images, err := c.runtime.Images()
	if err != nil {
		return err
	}
	defer images.Close()
	_, err = images.Pull(ctx, imageName)
	return err
}

// RemoveImage removes a cached image.
func (c *Client) RemoveImage(ctx context.Context, imageName string, force bool) error {
	c.logger.Warn("remove image not yet implemented in BoxLite", "image", imageName)
	return errdefs.ErrNotImplemented.WithMessage("image removal is not supported by the BoxLite Go SDK")
}

// ImageExists checks if an image is cached locally.
func (c *Client) ImageExists(ctx context.Context, imageName string) (bool, error) {
	images, err := c.ListImages(ctx)
	if err != nil {
		return false, err
	}
	for _, img := range images {
		if img.Reference == imageName || img.Repository+":"+img.Tag == imageName {
			return true, nil
		}
	}
	return false, nil
}

// GetImageInfo returns metadata about a cached image.
func (c *Client) GetImageInfoFromCache(ctx context.Context, imageName string) (*boxlite.ImageInfo, error) {
	images, err := c.ListImages(ctx)
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		if img.Reference == imageName || img.Repository+":"+img.Tag == imageName {
			return &img, nil
		}
	}
	return nil, fmt.Errorf("image not found: %s", imageName)
}

// ListImages returns all locally cached images.
func (c *Client) ListImages(ctx context.Context) ([]boxlite.ImageInfo, error) {
	images, err := c.runtime.Images()
	if err != nil {
		return nil, err
	}
	defer images.Close()
	return images.List(ctx)
}

// Ping checks if the BoxLite runtime is healthy.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.runtime.Metrics(ctx)
	return err
}

// Metrics returns runtime-level metrics.
func (c *Client) Metrics(ctx context.Context) (*boxlite.RuntimeMetrics, error) {
	return c.runtime.Metrics(ctx)
}

// BoxMetrics returns metrics for a specific sandbox.
func (c *Client) BoxMetrics(ctx context.Context, sandboxId string) (*boxlite.BoxMetrics, error) {
	bx, err := c.getOrFetchBox(ctx, sandboxId)
	if err != nil {
		return nil, err
	}
	return bx.Metrics(ctx)
}

// ListInfo returns info for all boxes managed by this runtime.
func (c *Client) ListInfo(ctx context.Context) ([]boxlite.BoxInfo, error) {
	return c.runtime.ListInfo(ctx)
}

// GetBox retrieves a box handle from cache or fetches it from the runtime.
func (c *Client) GetBox(ctx context.Context, sandboxId string) (*boxlite.Box, error) {
	return c.getOrFetchBox(ctx, sandboxId)
}

// getOrFetchBox retrieves a box handle from cache or fetches it from the runtime.
func (c *Client) getOrFetchBox(ctx context.Context, sandboxId string) (*boxlite.Box, error) {
	c.mu.RLock()
	bx, ok := c.boxes[sandboxId]
	c.mu.RUnlock()

	if ok {
		return bx, nil
	}

	bx, err := c.runtime.Get(ctx, sandboxId)
	if err != nil {
		return nil, fmt.Errorf("box %s not found: %w", sandboxId, err)
	}

	c.mu.Lock()
	c.boxes[sandboxId] = bx
	c.mu.Unlock()

	return bx, nil
}

// ExecResult holds the output of a command execution.
type ExecResult struct {
	StdOut   string
	StdErr   string
	ExitCode int
}
