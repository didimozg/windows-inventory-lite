package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// selfUpdateResponse mirrors the relevant slice of the inventory ack's
// JSON body - a separate, narrower struct from applyConfigFromServer's
// own response struct in config.go, since self-update is a distinct
// concern (network download, hash verification, subprocess exec) from
// config.go's file-rewrite-only responsibilities.
type selfUpdateResponse struct {
	Config struct {
		Update struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"update"`
	} `json:"config"`
}

// downloadFunc and verifyFunc are injected so tests can substitute fakes
// for the two operations that would otherwise need a real network call
// and a real second binary on disk - mirroring config.go's own
// reloadAndRestartTimer injection pattern.
type downloadFunc func(url, token string) ([]byte, error)
type verifyFunc func(binaryPath string) error

// ApplySelfUpdate is the real entry point called from the main report
// loop.
func ApplySelfUpdate(body []byte, binaryPath string, downloadURL string, token string) error {
	return applySelfUpdate(body, binaryPath, downloadURL, token, downloadClientPackage, verifyBinaryLaunches)
}

func applySelfUpdate(body []byte, binaryPath string, downloadURL string, token string, download downloadFunc, verify verifyFunc) error {
	if len(body) == 0 {
		return nil
	}

	var response selfUpdateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		// A malformed/unparseable response must never fail a report the
		// server has already accepted - same principle as
		// applyConfigFromServer in config.go.
		return nil
	}

	if response.Config.Update.Version == "" || response.Config.Update.SHA256 == "" {
		return nil
	}

	newContent, err := download(downloadURL, token)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}

	sum := sha256.Sum256(newContent)
	actualHash := hex.EncodeToString(sum[:])
	if actualHash != response.Config.Update.SHA256 {
		// Hash mismatch - never touch the real binary. The server will
		// keep advertising the same update; retried automatically on the
		// next run.
		return nil
	}

	backupPath := binaryPath + ".bak"
	if err := copyFile(binaryPath, backupPath); err != nil {
		return fmt.Errorf("back up current binary: %w", err)
	}

	// Write to a sibling temp file, not directly onto binaryPath - the
	// kernel returns ETXTBSY ("text file busy") when opening a currently-
	// executing binary for write/truncate, which binaryPath always is
	// here (it's os.Args[0]). A rename onto the same path IS allowed
	// while it's running (the old inode stays valid via the process's
	// existing mapping/open descriptor) - this is the standard pattern
	// for a Linux process replacing its own executable.
	stagingPath := binaryPath + ".new"
	if err := os.WriteFile(stagingPath, newContent, 0755); err != nil {
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := os.Rename(stagingPath, binaryPath); err != nil {
		_ = os.Remove(stagingPath)
		return fmt.Errorf("rename staged binary into place: %w", err)
	}

	// Verify from the OUTSIDE, in this same run, before committing - a
	// binary that fails to even launch can never run its own rollback
	// code if invoked cold by systemd on some later run. See this
	// feature's design spec for why this is not deferred to "next run
	// detects and rolls back".
	if verifyErr := verify(binaryPath); verifyErr != nil {
		if restoreErr := os.Rename(backupPath, binaryPath); restoreErr != nil {
			return fmt.Errorf("verification failed (%v) AND rollback failed (%w) - manual intervention required", verifyErr, restoreErr)
		}
		return nil
	}

	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("remove backup after successful update: %w", err)
	}
	return nil
}

func copyFile(sourcePath string, destinationPath string) error {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	return os.WriteFile(destinationPath, content, info.Mode())
}

// downloadClientPackage is the real HTTP download - the only part of
// this file that makes a network call, kept separate so tests can
// inject a fake in its place.
func downloadClientPackage(url, token string) ([]byte, error) {
	return httpGetBytes(url, token)
}

// verifyBinaryLaunches runs the newly-swapped binary once, in a
// side-effect-free mode (--version, which this client already supports
// - prints ClientVersion and exits 0), with a bounded timeout - the
// only part of this file that shells out to the binary being verified.
func verifyBinaryLaunches(binaryPath string) error {
	ctx, cancel := contextWithTimeout(5 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verification run failed: %w", err)
	}
	return nil
}

func httpGetBytes(url, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Inventory-Token", token)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
