package main

import "testing"

func TestResolveIngestionTokenPrefersEnvironment(t *testing.T) {
	// systemd delivers the token via EnvironmentFile (mode 600) rather than on
	// the ExecStart command line, where any local user could read it from
	// /proc/<pid>/cmdline.
	got := ResolveIngestionToken("env-token", "flag-token")
	if got != "env-token" {
		t.Errorf("got %q, want %q", got, "env-token")
	}
}

func TestResolveIngestionTokenFallsBackToFlag(t *testing.T) {
	// Standalone/manual runs have no EnvironmentFile, so --token still works.
	got := ResolveIngestionToken("", "flag-token")
	if got != "flag-token" {
		t.Errorf("got %q, want %q", got, "flag-token")
	}
}

func TestResolveIngestionTokenEmptyWhenNeitherIsSet(t *testing.T) {
	got := ResolveIngestionToken("", "")
	if got != "" {
		t.Errorf("got %q, want an empty token", got)
	}
}
