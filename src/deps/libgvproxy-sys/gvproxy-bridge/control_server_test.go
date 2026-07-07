package main

import (
	"context"
	"testing"
)

// TestStartControlServer_ListenFailureIsReported proves that startControlServer
// surfaces a Unix-socket listen failure to its caller instead of only logging
// it. gvproxy_create's caller (the Rust runtime) relies on this: before this
// fix, a control-socket failure was logged and swallowed, so gvproxy_create
// returned a valid instance id with a broken ServicesMux control plane — the
// box would never be able to enable real-SSH access (or any other
// ServicesMux-dependent feature), and the only symptom would surface much
// later as a mysterious "SSH port forwarding unavailable" failure rather than
// an init-time error.
func TestStartControlServer_ListenFailureIsReported(t *testing.T) {
	// A path under a directory that doesn't exist makes net.Listen("unix", ...)
	// fail with "no such file or directory" — vn is never dereferenced on this
	// path (the listen failure returns before vn.ServicesMux() is called), so
	// passing nil is safe here.
	err := startControlServer(context.Background(), nil, "/nonexistent-dir-boxlite-test/control.sock")
	if err == nil {
		t.Fatal("startControlServer succeeded despite a nonexistent parent directory; " +
			"expected a Unix-socket listen error to be returned")
	}
}
