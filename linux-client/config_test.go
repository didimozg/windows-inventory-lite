package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteTimerInterval(t *testing.T) {
	tests := []struct {
		name        string
		unitContent string
		newValue    int
		unitSuffix  string
		wantChanged bool
		wantLine    string
	}{
		{
			name:        "changes a different hours interval on the main report timer",
			unitContent: "[Unit]\nDescription=WIL report timer\n\n[Timer]\nOnUnitActiveSec=6h\nUnit=wil-linux-client.service\n\n[Install]\nWantedBy=timers.target\n",
			newValue:    12,
			unitSuffix:  "h",
			wantChanged: true,
			wantLine:    "OnUnitActiveSec=12h",
		},
		{
			name:        "no-op when the main report timer is already at the target value",
			unitContent: "[Unit]\nDescription=WIL report timer\n\n[Timer]\nOnUnitActiveSec=6h\nUnit=wil-linux-client.service\n\n[Install]\nWantedBy=timers.target\n",
			newValue:    6,
			unitSuffix:  "h",
			wantChanged: false,
			wantLine:    "OnUnitActiveSec=6h",
		},
		{
			// The status timer uses a different suffix than the main report
			// timer (minutes, not hours - see GenerateSystemdStatusTimerLines
			// server-side). rewriteTimerInterval must handle both through the
			// same regex, driven by the unitSuffix parameter.
			name:        "changes a different minutes interval on the status timer",
			unitContent: "[Unit]\nDescription=WIL status timer\n\n[Timer]\nOnUnitActiveSec=30min\nUnit=wil-linux-client-status.service\n\n[Install]\nWantedBy=timers.target\n",
			newValue:    15,
			unitSuffix:  "min",
			wantChanged: true,
			wantLine:    "OnUnitActiveSec=15min",
		},
		{
			name:        "no-op when the status timer is already at the target value",
			unitContent: "[Unit]\nDescription=WIL status timer\n\n[Timer]\nOnUnitActiveSec=30min\nUnit=wil-linux-client-status.service\n\n[Install]\nWantedBy=timers.target\n",
			newValue:    30,
			unitSuffix:  "min",
			wantChanged: false,
			wantLine:    "OnUnitActiveSec=30min",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			unitPath := filepath.Join(dir, "wil-linux-client.timer")
			if err := os.WriteFile(unitPath, []byte(tt.unitContent), 0644); err != nil {
				t.Fatalf("write test unit file: %v", err)
			}

			changed, err := rewriteTimerInterval(unitPath, tt.newValue, tt.unitSuffix)
			if err != nil {
				t.Fatalf("rewriteTimerInterval returned error: %v", err)
			}
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}

			result, err := os.ReadFile(unitPath)
			if err != nil {
				t.Fatalf("read result: %v", err)
			}
			if !strings.Contains(string(result), tt.wantLine) {
				t.Errorf("expected result to contain %q, got:\n%s", tt.wantLine, string(result))
			}
			// Every other line must survive untouched.
			if !strings.Contains(string(result), "Unit=") || !strings.Contains(string(result), "WantedBy=timers.target") {
				t.Errorf("expected non-interval lines to be preserved, got:\n%s", string(result))
			}
		})
	}
}

func TestApplyConfigFromServerRewritesEnvToken(t *testing.T) {
	dir := t.TempDir()
	timerPath := filepath.Join(dir, "wil-linux-client.timer")
	statusTimerPath := filepath.Join(dir, "wil-linux-client-status.timer")
	envPath := filepath.Join(dir, "wil-linux-client.env")

	if err := os.WriteFile(timerPath, []byte("[Timer]\nOnUnitActiveSec=6h\n"), 0644); err != nil {
		t.Fatalf("write timer fixture: %v", err)
	}
	if err := os.WriteFile(statusTimerPath, []byte("[Timer]\nOnUnitActiveSec=30min\n"), 0644); err != nil {
		t.Fatalf("write status timer fixture: %v", err)
	}
	if err := os.WriteFile(envPath, []byte("WIL_INGESTION_TOKEN=old-token\n"), 0644); err != nil {
		t.Fatalf("write env fixture: %v", err)
	}

	body := []byte(`{"status":"ok","config":{"intervalHours":6,"statusIntervalMinutes":30,"ingestionToken":"new-token"}}`)

	if err := applyConfigFromServerForTest(body, timerPath, statusTimerPath, envPath); err != nil {
		t.Fatalf("ApplyConfigFromServer returned error: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(result), "WIL_INGESTION_TOKEN=new-token") {
		t.Errorf("expected env file to contain the new token, got:\n%s", string(result))
	}
	if strings.Contains(string(result), "old-token") {
		t.Errorf("expected old token to be fully replaced, got:\n%s", string(result))
	}
}

// A real, confirmed bug: regexp.ReplaceAll interprets "$" in the
// REPLACEMENT text as submatch-expansion syntax ($1, ${name}, $$ for a
// literal "$") even though the pattern here has zero capture groups.
// The server's own auto-generated tokens (64 lowercase hex) never
// contain "$", but an operator-chosen custom token (--token/config, no
// charset restriction) can - this guards against a silent, no-error
// corruption of exactly that case.
func TestRewriteEnvTokenHandlesDollarSignsInToken(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "wil-linux-client.env")
	if err := os.WriteFile(envPath, []byte("WIL_INGESTION_TOKEN=old-token\n"), 0644); err != nil {
		t.Fatalf("write env fixture: %v", err)
	}

	tokenWithDollarSigns := "abc$1def${2}ghi$$end"
	if err := rewriteEnvToken(envPath, tokenWithDollarSigns); err != nil {
		t.Fatalf("rewriteEnvToken returned error: %v", err)
	}

	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	expected := "WIL_INGESTION_TOKEN=" + tokenWithDollarSigns
	if !strings.Contains(string(result), expected) {
		t.Errorf("expected the token to be written verbatim, dollar signs intact - got:\n%s\nwanted line: %s", string(result), expected)
	}
}

// applyConfigFromServerForTest is a test-only seam: the real
// ApplyConfigFromServer always wires reloadAndRestartTimer, which shells
// out to systemctl - not available in a test environment (and on this
// Windows dev machine, os.Geteuid() never returns 0 anyway, so the
// timer-rewrite branches never fire here regardless; only the
// unconditional ingestionToken rewrite is exercised by this test). This
// wrapper calls the real applyConfigFromServer with a no-op reload so the
// test can call it without a real systemd.
func applyConfigFromServerForTest(body []byte, timerUnitPath, statusTimerUnitPath, envFilePath string) error {
	noopReload := func(unitName string) error { return nil }
	return applyConfigFromServer(body, timerUnitPath, statusTimerUnitPath, envFilePath, noopReload)
}
