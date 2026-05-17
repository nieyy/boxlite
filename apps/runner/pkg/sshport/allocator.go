// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

// Package sshport manages host port allocation for VM SSH access.
package sshport

import (
	"fmt"
	"sync"
)

// Allocator manages host port allocation for VM SSH access.
// Ports are drawn sequentially from [BasePort, BasePort+PoolSize).
type Allocator struct {
	mu       sync.Mutex
	basePort int
	poolSize int
	used     map[int]string // port → boxId
	byBox    map[string]int // boxId → port
}

// NewAllocator creates an allocator for the port range [basePort, basePort+poolSize).
func NewAllocator(basePort, poolSize int) *Allocator {
	return &Allocator{
		basePort: basePort,
		poolSize: poolSize,
		used:     make(map[int]string),
		byBox:    make(map[string]int),
	}
}

// Allocate assigns a free port to boxId. Returns an existing port if boxId
// already has one (idempotent). Returns an error if the pool is exhausted.
func (a *Allocator) Allocate(boxId string) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if p, ok := a.byBox[boxId]; ok {
		return p, nil
	}

	for i := 0; i < a.poolSize; i++ {
		port := a.basePort + i
		if _, inUse := a.used[port]; !inUse {
			a.used[port] = boxId
			a.byBox[boxId] = port
			return port, nil
		}
	}

	return 0, fmt.Errorf("SSH port pool exhausted (pool size %d, base %d)", a.poolSize, a.basePort)
}

// Release frees the port held by boxId. No-op if boxId has no allocation.
func (a *Allocator) Release(boxId string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	port, ok := a.byBox[boxId]
	if !ok {
		return
	}
	delete(a.used, port)
	delete(a.byBox, boxId)
}

// GetPort returns the port allocated to boxId and whether it exists.
func (a *Allocator) GetPort(boxId string) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	port, ok := a.byBox[boxId]
	return port, ok
}

// ReservePort records a pre-existing port allocation for boxId without scanning
// the free list. It is used during startup reconciliation to restore SSH state
// that was persisted to disk before a runner restart.
//
// Returns an error if the port is outside the allocator range or is already
// held by a different box. If boxId already owns this exact port the call is
// a no-op (idempotent). If boxId already owns a DIFFERENT port, that old port
// is released before recording the new one, preventing pool leaks when stale
// or duplicate persisted records call ReservePort twice for the same box.
func (a *Allocator) ReservePort(boxId string, port int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if port < a.basePort || port >= a.basePort+a.poolSize {
		return fmt.Errorf("port %d is outside allocator range [%d, %d)", port, a.basePort, a.basePort+a.poolSize)
	}

	// Idempotent: box already owns this exact port — no state change needed.
	if existingPort, ok := a.byBox[boxId]; ok && existingPort == port {
		return nil
	}

	// Reject if the target port is taken by a different box BEFORE releasing the
	// caller's current allocation. Checking first makes the operation atomic: if
	// the target is unavailable we return an error without touching any state,
	// keeping used and byBox consistent.
	if owner, inUse := a.used[port]; inUse && owner != boxId {
		return fmt.Errorf("port %d is already allocated to box %s", port, owner)
	}

	// Target is available. Release the caller's old port (if any) so it re-enters
	// the pool, then record the new assignment.
	if existingPort, ok := a.byBox[boxId]; ok {
		delete(a.used, existingPort)
	}

	a.used[port] = boxId
	a.byBox[boxId] = port
	return nil
}
