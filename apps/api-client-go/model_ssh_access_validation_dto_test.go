package apiclient

import (
	"encoding/json"
	"testing"
)

// Reproducer for Finding 1, Round 67: ToMap() omits UnixUser, so MarshalJSON
// silently drops the field. Any re-serialization of a real-SSH validation DTO
// loses the unixUser field, causing HasUnixUser() to return false on the
// re-parsed object — every real-SSH token appears as a legacy exec-bridge token.
func TestSshAccessValidationDtoToMapPreservesUnixUser(t *testing.T) {
	user := "boxlite"
	original := &SshAccessValidationDto{
		Valid:     true,
		SandboxId: "sandbox-abc",
		UnixUser:  &user,
	}

	// MarshalJSON delegates to ToMap(); if ToMap() drops UnixUser, re-parsing
	// will produce a struct with UnixUser == nil.
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var roundTripped SshAccessValidationDto
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if !roundTripped.HasUnixUser() {
		t.Errorf("HasUnixUser() = false after JSON round-trip; serialized JSON: %s", string(data))
	}
	if roundTripped.GetUnixUser() != user {
		t.Errorf("GetUnixUser() = %q, want %q", roundTripped.GetUnixUser(), user)
	}
}

// Documents the contract for empty-string UnixUser (non-nil *string pointing to ""):
// HasUnixUser()=true and GetUnixUser()="" — treated as a real-SSH token with empty user.
// This should never appear in practice (controller coerces empty string to null), but the
// behavior must be documented so a future change to HasUnixUser() (treating "" as nil)
// is a deliberate, test-verified decision rather than an accidental regression.
func TestSshAccessValidationDtoEmptyStringUnixUser(t *testing.T) {
	empty := ""
	dto := &SshAccessValidationDto{
		Valid:     true,
		SandboxId: "sandbox-abc",
		UnixUser:  &empty,
	}

	// Empty-string pointer: HasUnixUser returns true (non-nil pointer), GetUnixUser returns "".
	// If the gateway ever receives this, it will treat it as tokenIsSSHAccess=true with user="",
	// which would fail at the SSH protocol level. The controller prevents this via || normalization.
	if !dto.HasUnixUser() {
		t.Error("HasUnixUser() = false for non-nil empty-string pointer; want true (current contract)")
	}
	if dto.GetUnixUser() != "" {
		t.Errorf("GetUnixUser() = %q, want empty string", dto.GetUnixUser())
	}
}

// Companion: null UnixUser must remain null after round-trip (exec-bridge token).
func TestSshAccessValidationDtoToMapPreservesNullUnixUser(t *testing.T) {
	original := &SshAccessValidationDto{
		Valid:     true,
		SandboxId: "sandbox-abc",
		UnixUser:  nil,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var roundTripped SshAccessValidationDto
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if roundTripped.HasUnixUser() {
		t.Errorf("HasUnixUser() = true for exec-bridge token after round-trip; want false")
	}
}
