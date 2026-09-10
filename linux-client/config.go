package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"windows-inventory-lite/linux-client/collect"
)

// onUnitActiveSecPattern matches a systemd timer's OnUnitActiveSec= line
// regardless of its unit suffix. The two timer files this client owns use
// different suffixes: GenerateSystemdTimerLines (server side, main report
// timer) emits an hours suffix ("OnUnitActiveSec=6h"), while
// GenerateSystemdStatusTimerLines (status-ping timer) emits a minutes
// suffix ("OnUnitActiveSec=30min") - confirmed against the real
// server-generated unit content in src/server/WindowsInventoryLiteServer.cs,
// not assumed. Matching digits followed by any letters (rather than a
// hardcoded "h?") lets rewriteTimerInterval handle both formats through the
// same regex; the caller supplies which suffix to write back.
var onUnitActiveSecPattern = regexp.MustCompile(`(?m)^OnUnitActiveSec=\d+[A-Za-z]*\s*$`)

// rewriteTimerInterval rewrites unitPath's OnUnitActiveSec= line to
// "<newValue><unitSuffix>", leaving every other line untouched. unitSuffix
// is "h" for the main report timer (wil-linux-client.timer) or "min" for
// the status timer (wil-linux-client-status.timer) - see
// onUnitActiveSecPattern's comment for why the two differ.
// Returns whether a change was actually made (false if the file already
// had the requested value) so the caller can skip the systemctl reload
// entirely when nothing changed.
func rewriteTimerInterval(unitPath string, newValue int, unitSuffix string) (bool, error) {
	content, err := os.ReadFile(unitPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", unitPath, err)
	}

	if !onUnitActiveSecPattern.Match(content) {
		return false, fmt.Errorf("%s has no OnUnitActiveSec= line", unitPath)
	}

	newLine := "OnUnitActiveSec=" + strconv.Itoa(newValue) + unitSuffix
	// Compare the FULL before/after content, not just the first regex
	// match - a unit file with a duplicated OnUnitActiveSec= line whose
	// first occurrence already matched newLine would previously report
	// "no change" and skip fixing a stale second occurrence (only
	// reachable with an already-malformed unit file, but cheap to make
	// correct regardless of match count).
	updated := onUnitActiveSecPattern.ReplaceAll(content, []byte(newLine))
	if bytes.Equal(updated, content) {
		return false, nil
	}
	if err := os.WriteFile(unitPath, updated, 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", unitPath, err)
	}
	return true, nil
}

// rewriteEnvToken rewrites envFilePath's WIL_INGESTION_TOKEN= line,
// preserving every other line - mirrors rewriteTimerInterval's own
// single-line-replace approach.
func rewriteEnvToken(envFilePath string, newToken string) error {
	content, err := os.ReadFile(envFilePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", envFilePath, err)
	}
	pattern := regexp.MustCompile(`(?m)^WIL_INGESTION_TOKEN=.*$`)
	newLine := "WIL_INGESTION_TOKEN=" + newToken
	var updated []byte
	if pattern.Match(content) {
		// regexp.ReplaceAll interprets "$" in the REPLACEMENT text as
		// submatch-expansion syntax ($1, ${name}, $$ for a literal "$"),
		// even though this pattern has zero capture groups - confirmed
		// empirically: a token containing "$1"/"${x}"/"$$" was silently
		// corrupted on write (e.g. "abc$1def" -> "abc"), no error. The
		// server's auto-generated tokens (64 lowercase hex) never
		// contain "$", but an operator-chosen custom token
		// (--token/config, no charset restriction) can. Escaping every
		// literal "$" in the replacement text (doubling it to "$$") is
		// the documented way to tell ReplaceAll it's not a submatch
		// reference.
		escapedNewLine := strings.Replace(newLine, "$", "$$", -1)
		updated = pattern.ReplaceAll(content, []byte(escapedNewLine))
	} else {
		updated = append(content, []byte("\n"+newLine+"\n")...)
	}
	return os.WriteFile(envFilePath, updated, 0644)
}

// reloadAndRestartTimer runs `systemctl daemon-reload` followed by
// `systemctl restart <timerUnitName>` - the only part of this file that
// shells out, kept separate from rewriteTimerInterval's pure file logic
// specifically so tests can inject a no-op in place of this function
// without needing a real systemd.
//
// Uses collect.SystemctlPath (an absolute path), not a bare "systemctl"
// resolved through PATH - this function only ever runs as root (see its
// only caller's own os.Geteuid()==0 gate), and collect.SystemctlPath's
// own comment documents why a PATH lookup is a real local-privilege-
// escalation vector for a root-run systemd service on this project's
// target distros. This was the one place in this codebase that still
// used the bare, PATH-resolved form.
func reloadAndRestartTimer(timerUnitName string) error {
	if err := exec.Command(collect.SystemctlPath, "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command(collect.SystemctlPath, "restart", timerUnitName).Run(); err != nil {
		return fmt.Errorf("systemctl restart %s: %w", timerUnitName, err)
	}
	return nil
}

// ApplyConfigFromServer is the real entry point called from the main
// report loop - reloadAndRestartTimer is always the real function here;
// applyConfigFromServer (lowercase, unexported) takes it as a parameter
// so config_test.go can substitute a no-op instead.
func ApplyConfigFromServer(body []byte, timerUnitPath string, statusTimerUnitPath string, envFilePath string) error {
	return applyConfigFromServer(body, timerUnitPath, statusTimerUnitPath, envFilePath, reloadAndRestartTimer)
}

func applyConfigFromServer(body []byte, timerUnitPath string, statusTimerUnitPath string, envFilePath string, reload func(timerUnitName string) error) error {
	if len(body) == 0 {
		return nil
	}

	var response struct {
		Config struct {
			IntervalHours         int    `json:"intervalHours"`
			StatusIntervalMinutes int    `json:"statusIntervalMinutes"`
			IngestionToken        string `json:"ingestionToken"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		// A malformed/unparseable response must never fail a report the
		// server has already accepted - same principle as the Windows
		// client's ApplyInventoryAckResponse.
		return nil
	}

	if response.Config.IntervalHours >= 1 && response.Config.IntervalHours <= 24 {
		if os.Geteuid() != 0 {
			// Not running as root - can't safely rewrite/reload a
			// systemd unit. Skip rather than fail; the next run (which
			// may or may not be root, depending on deployment) will see
			// the same instruction again from the server and retry.
			log.Printf("skipping systemd interval timer rewrite: not running as root")
		} else {
			changed, err := rewriteTimerInterval(timerUnitPath, response.Config.IntervalHours, "h")
			if err != nil {
				return fmt.Errorf("rewrite interval timer: %w", err)
			}
			if changed {
				if err := reload("wil-linux-client.timer"); err != nil {
					return fmt.Errorf("reload interval timer: %w", err)
				}
			}
		}
	}

	if response.Config.StatusIntervalMinutes >= 1 && response.Config.StatusIntervalMinutes <= 1440 {
		if os.Geteuid() == 0 {
			changed, err := rewriteTimerInterval(statusTimerUnitPath, response.Config.StatusIntervalMinutes, "min")
			if err != nil {
				return fmt.Errorf("rewrite status timer: %w", err)
			}
			if changed {
				if err := reload("wil-linux-client-status.timer"); err != nil {
					return fmt.Errorf("reload status timer: %w", err)
				}
			}
		} else {
			// Not running as root - can't safely rewrite/reload a
			// systemd unit. Skip rather than fail; the next run (which
			// may or may not be root, depending on deployment) will see
			// the same instruction again from the server and retry.
			log.Printf("skipping systemd status timer rewrite: not running as root")
		}
	}

	if response.Config.IngestionToken != "" {
		if err := rewriteEnvToken(envFilePath, response.Config.IngestionToken); err != nil {
			return fmt.Errorf("rewrite ingestion token: %w", err)
		}
	}

	return nil
}
