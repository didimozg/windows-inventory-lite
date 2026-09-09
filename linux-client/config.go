package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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
	current := onUnitActiveSecPattern.Find(content)
	if string(current) == newLine {
		return false, nil
	}

	updated := onUnitActiveSecPattern.ReplaceAll(content, []byte(newLine))
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
		updated = pattern.ReplaceAll(content, []byte(newLine))
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
func reloadAndRestartTimer(timerUnitName string) error {
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "restart", timerUnitName).Run(); err != nil {
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
