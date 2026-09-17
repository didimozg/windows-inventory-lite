package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
			Sig     string `json:"sig"`
		} `json:"update"`
	} `json:"config"`
}

// downloadFunc, verifyFunc, and isRootFunc are injected so tests can
// substitute fakes for the operations that would otherwise need a real
// network call, a real second binary on disk, or a real root process -
// mirroring config.go's own reloadAndRestartTimer injection pattern.
type downloadFunc func(url, token string) ([]byte, error)
type verifyFunc func(binaryPath string) error
type isRootFunc func() bool

// isVersionNewer/parseVersionParts port the Windows client's own
// IsVersionNewer/ParseVersionParts (WindowsInventoryLiteClient.cs) -
// same dotted-integer-segment comparison, same "unparseable counts as
// not newer" rule. Ported rather than shared because the two clients
// don't share a build - see this project's own established precedent
// for this class of unavoidable cross-language duplication (already
// used for the self-update download/verify injection pattern).
func isVersionNewer(candidateVersion string, currentVersion string) bool {
	candidateParts := parseVersionParts(candidateVersion)
	currentParts := parseVersionParts(currentVersion)
	if candidateParts == nil || currentParts == nil {
		return false
	}
	length := len(candidateParts)
	if len(currentParts) > length {
		length = len(currentParts)
	}
	for i := 0; i < length; i++ {
		candidatePart := 0
		if i < len(candidateParts) {
			candidatePart = candidateParts[i]
		}
		currentPart := 0
		if i < len(currentParts) {
			currentPart = currentParts[i]
		}
		if candidatePart != currentPart {
			return candidatePart > currentPart
		}
	}
	return false
}

func parseVersionParts(version string) []int {
	if version == "" {
		return nil
	}
	segments := strings.Split(version, ".")
	parts := make([]int, len(segments))
	for i, segment := range segments {
		value, err := strconv.Atoi(strings.TrimSpace(segment))
		if err != nil {
			return nil
		}
		parts[i] = value
	}
	return parts
}

// verifySelfUpdateSignature checks an RSA/SHA256/PKCS#1v1.5 signature -
// the same scheme Sign-ClientRelease.ps1 produces via .NET's
// RSACryptoServiceProvider.SignData, and the Windows client's own
// VerifyRsaSignature checks. Returns false (never panics) for any
// malformed input.
func verifySelfUpdateSignature(data []byte, signatureBase64 string, publicKeyModulusBase64 string, publicKeyExponent int) bool {
	if signatureBase64 == "" || publicKeyModulusBase64 == "" {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false
	}
	modulusBytes, err := base64.StdEncoding.DecodeString(publicKeyModulusBase64)
	if err != nil {
		return false
	}
	publicKey := rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: publicKeyExponent}
	hashed := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], signature) == nil
}

// isRunningAsRoot is the real root check - a bare inline os.Geteuid() == 0
// call (config.go's own convention for this class of privileged operation)
// was tried directly in applySelfUpdate first and reverted: os.Geteuid()
// always returns -1 on a non-Linux dev machine, so a blanket inline gate
// made every existing applySelfUpdate test short-circuit before doing any
// real work, silently gutting their own coverage instead of skipping
// cleanly. Injecting it as a parameter (like download/verify above) lets
// tests force it true and keep exercising the real swap/verify/rollback
// logic.
func isRunningAsRoot() bool {
	return os.Geteuid() == 0
}

// selfUpdatePublicKeyModulusBase64/selfUpdatePublicKeyExponent are
// placeholders until the project owner runs the one-time key-generation
// step (docs/self-update-signing.md) and pastes the real values here - a
// placeholder key can never verify any real signature, which is safe
// since --require-signed-self-update is off by default.
var selfUpdatePublicKeyModulusBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
const selfUpdatePublicKeyExponent = 65537

// ApplySelfUpdate is the real entry point called from the main report
// loop.
func ApplySelfUpdate(body []byte, binaryPath string, downloadURL string, token string, currentVersion string, requireHTTPS bool, requireSignature bool) error {
	return applySelfUpdate(body, binaryPath, downloadURL, token, currentVersion, requireHTTPS, requireSignature, downloadClientPackage, verifyBinaryLaunches, isRunningAsRoot, selfUpdatePublicKeyModulusBase64, selfUpdatePublicKeyExponent)
}

func applySelfUpdate(body []byte, binaryPath string, downloadURL string, token string, currentVersion string, requireHTTPS bool, requireSignature bool, download downloadFunc, verify verifyFunc, isRoot isRootFunc, publicKeyModulusBase64 string, publicKeyExponent int) error {
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

	if !isVersionNewer(response.Config.Update.Version, currentVersion) {
		// Only ever move forward - same reasoning as the Windows client's
		// own IsVersionNewer check: a stale rebuild or a restored old
		// backup on the server would otherwise silently downgrade every
		// self-update-enabled Linux client that reports in while it's in
		// that state.
		return nil
	}

	if requireHTTPS && !strings.HasPrefix(downloadURL, "https://") {
		return nil
	}

	if !isRoot() {
		return nil
	}

	newContent, err := download(downloadURL, token)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}

	sum := sha256.Sum256(newContent)
	actualHash := hex.EncodeToString(sum[:])
	if actualHash != response.Config.Update.SHA256 {
		return nil
	}

	if requireSignature {
		if !verifySelfUpdateSignature(newContent, response.Config.Update.Sig, publicKeyModulusBase64, publicKeyExponent) {
			return nil
		}
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
		// binaryPath was never touched by this failure - the backup is
		// unused, not a restore-from-.bak case. Remove it rather than
		// leaving a stray, unnecessary copy next to the binary. Also
		// remove stagingPath itself: a write that fails partway (e.g.
		// ENOSPC) can leave a partial/zero-length file at this path
		// (os.WriteFile creates the file before it can fail on the write
		// itself) - this branch previously left that orphan behind,
		// unlike the Rename-failure branch below which already cleaned
		// up both paths.
		_ = os.Remove(stagingPath)
		_ = os.Remove(backupPath)
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := os.Rename(stagingPath, binaryPath); err != nil {
		// Same reasoning - a failed rename leaves binaryPath as whatever
		// it already was (rename is atomic on the same filesystem), so
		// there is nothing to restore, only an unused backup to clean up.
		_ = os.Remove(stagingPath)
		_ = os.Remove(backupPath)
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
