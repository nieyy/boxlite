// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package sshport

import (
	"testing"
)

// TestReservePortIdempotentAndNoLeak verifies three cases for ReservePort:
//
//  1. Idempotent: calling ReservePort for the same box+port twice is a no-op.
//  2. Box re-assignment: calling ReservePort for the same box with a DIFFERENT port
//     releases the old port so it can be re-used by another box.
//  3. No pool leak: after re-assignment, the old port is free and Allocate can
//     hand it out to another caller.
func TestReservePortIdempotentAndNoLeak(t *testing.T) {
	const base = 22100
	const pool = 10
	a := NewAllocator(base, pool)

	// 1. First reservation succeeds.
	if err := a.ReservePort("box1", 22100); err != nil {
		t.Fatalf("first ReservePort(box1, 22100): unexpected error: %v", err)
	}

	// 2. Idempotent: same box, same port — must return nil without changing state.
	if err := a.ReservePort("box1", 22100); err != nil {
		t.Fatalf("idempotent ReservePort(box1, 22100): unexpected error: %v", err)
	}
	if p, ok := a.GetPort("box1"); !ok || p != 22100 {
		t.Fatalf("after idempotent reserve: expected box1→22100, got ok=%v port=%d", ok, p)
	}

	// 3. Same box, different port — must release 22100 and take 22101.
	if err := a.ReservePort("box1", 22101); err != nil {
		t.Fatalf("re-assignment ReservePort(box1, 22101): unexpected error: %v", err)
	}
	if p, ok := a.GetPort("box1"); !ok || p != 22101 {
		t.Fatalf("after re-assignment: expected box1→22101, got ok=%v port=%d", ok, p)
	}

	// 4. Port 22100 must now be free: Allocate("box2") should return 22100
	//    (it is the first free port in the sequential scan).
	got, err := a.Allocate("box2")
	if err != nil {
		t.Fatalf("Allocate(box2) after release: unexpected error: %v", err)
	}
	if got != 22100 {
		t.Fatalf("expected box2 to get freed port 22100, got %d", got)
	}
}

// TestReservePortOutOfRange verifies that ports outside the pool are rejected.
func TestReservePortOutOfRange(t *testing.T) {
	a := NewAllocator(22100, 10)

	if err := a.ReservePort("box1", 22099); err == nil {
		t.Fatal("expected error for port below base, got nil")
	}
	if err := a.ReservePort("box1", 22110); err == nil {
		t.Fatal("expected error for port at/above ceiling, got nil")
	}
}

// TestReservePortConflict verifies that a port already held by another box is rejected.
func TestReservePortConflict(t *testing.T) {
	a := NewAllocator(22100, 10)

	if err := a.ReservePort("box1", 22100); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := a.ReservePort("box2", 22100); err == nil {
		t.Fatal("expected error when reserving a port owned by another box, got nil")
	}
}

// TestReservePortConflictDoesNotLeakOldPort verifies that when ReservePort fails
// because the target port is held by another box, the calling box retains its
// original allocation and the original port cannot be stolen by a third box.
//
// Regression: before the fix, ReservePort released the caller's old port from the
// used map before checking the conflict, leaving used and byBox inconsistent on
// error. A subsequent Allocate could hand out the now-unprotected old port while
// byBox still pointed the original box at the same port — two boxes sharing a port.
func TestReservePortConflictDoesNotLeakOldPort(t *testing.T) {
	const base = 22100
	const pool = 10
	a := NewAllocator(base, pool)

	// box1 owns 22100, box2 owns 22101.
	if err := a.ReservePort("box1", 22100); err != nil {
		t.Fatalf("setup box1: %v", err)
	}
	if err := a.ReservePort("box2", 22101); err != nil {
		t.Fatalf("setup box2: %v", err)
	}

	// Attempt to move box1 to 22101 — must fail (owned by box2).
	if err := a.ReservePort("box1", 22101); err == nil {
		t.Fatal("expected conflict error, got nil")
	}

	// box1 must still own 22100.
	p1, ok1 := a.GetPort("box1")
	if !ok1 || p1 != 22100 {
		t.Fatalf("after failed ReservePort: box1 should still own 22100, got ok=%v port=%d", ok1, p1)
	}

	// 22100 must not be available for allocation to a third box.
	// Allocate scans from base; the first free port after 22100 and 22101 are both
	// reserved is 22102.
	got, err := a.Allocate("box3")
	if err != nil {
		t.Fatalf("Allocate(box3): unexpected error: %v", err)
	}
	if got == 22100 {
		t.Fatalf("Allocate(box3) returned 22100, which is still owned by box1 — port leak detected")
	}
	if got != 22102 {
		t.Fatalf("expected box3 to get 22102 (first free port), got %d", got)
	}
}
