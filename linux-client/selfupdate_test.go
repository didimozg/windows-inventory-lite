package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplySelfUpdateSwapsBinaryWhenHashMatchesAndVerificationSucceeds(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("new-binary-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
			},
		},
	})

	fakeDownload := func(url, token string) ([]byte, error) { return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.1.0", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}

	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read swapped binary: %v", err)
	}
	if string(result) != string(newContent) {
		t.Errorf("expected binary to be swapped to new content, got: %s", result)
	}
	if _, err := os.Stat(binaryPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("expected .bak to be removed after a successful verification, got err=%v", err)
	}
}

func TestApplySelfUpdateRollsBackWhenVerificationFails(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("broken-binary-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
			},
		},
	})

	fakeDownload := func(url, token string) ([]byte, error) { return newContent, nil }
	fakeVerify := func(path string) error { return errors.New("simulated: new binary fails to launch") }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.1.0", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error (rollback failure should not itself be an error): %v", err)
	}

	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary after rollback: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected binary to be rolled back to old content after failed verification, got: %s", result)
	}
	if _, err := os.Stat(binaryPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("expected .bak to be removed after rollback, got err=%v", err)
	}
}

func TestApplySelfUpdateSkipsWhenHashMismatches(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  "0000000000000000000000000000000000000000000000000000000000000",
			},
		},
	})

	verifyCalled := false
	fakeDownload := func(url, token string) ([]byte, error) { return []byte("wrong-content"), nil }
	fakeVerify := func(path string) error { verifyCalled = true; return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.1.0", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}

	if verifyCalled {
		t.Error("expected verification to be skipped entirely on a hash mismatch")
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected binary to remain untouched on a hash mismatch, got: %s", result)
	}
}

func TestApplySelfUpdateNoOpsWhenNoUpdateField(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	body := []byte(`{"status":"ok","config":{"intervalHours":6}}`)
	downloadCalled := false
	fakeDownload := func(url, token string) ([]byte, error) { downloadCalled = true; return nil, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.1.0", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	if downloadCalled {
		t.Error("expected no download attempt when the response carries no update field")
	}
}

// A real gap this test closes: applySelfUpdate previously had no root
// check at all, unlike config.go's own established convention for this
// class of privileged operation (see isRunningAsRoot's own comment for
// why it's injected rather than a bare inline os.Geteuid() call). Without
// this gate, a non-root invocation would reach download() and the binary
// swap attempt and only fail there with a permission error, instead of
// skipping cleanly and retrying on a later run.
func TestApplySelfUpdateSkipsWhenNotRoot(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("new-binary-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
			},
		},
	})

	downloadCalled := false
	fakeDownload := func(url, token string) ([]byte, error) { downloadCalled = true; return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return false }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.1.0", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}

	if downloadCalled {
		t.Error("expected no download attempt when not running as root")
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected binary to remain untouched when not running as root, got: %s", result)
	}
}

func TestIsVersionNewerReturnsTrueForStrictlyGreaterVersion(t *testing.T) {
	if !isVersionNewer("1.2.10", "1.2.9") {
		t.Errorf("expected 1.2.10 to be newer than 1.2.9")
	}
}

func TestIsVersionNewerReturnsFalseForEqualVersion(t *testing.T) {
	if isVersionNewer("1.2.9", "1.2.9") {
		t.Errorf("expected 1.2.9 to not be newer than itself")
	}
}

func TestIsVersionNewerReturnsFalseForOlderVersion(t *testing.T) {
	if isVersionNewer("1.2.8", "1.2.9") {
		t.Errorf("expected 1.2.8 to not be newer than 1.2.9")
	}
}

func TestIsVersionNewerReturnsFalseForUnparseableVersion(t *testing.T) {
	if isVersionNewer("not-a-version", "1.2.9") {
		t.Errorf("expected an unparseable version to never count as newer")
	}
}

func TestApplySelfUpdateSkipsWhenAdvertisedVersionIsNotNewer(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("stale-server-build-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "0.1.0",
				"sha256":  newHash,
			},
		},
	})

	downloadCalled := false
	fakeDownload := func(url, token string) ([]byte, error) { downloadCalled = true; return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.2.3", false, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	if downloadCalled {
		t.Errorf("expected download to be skipped when the advertised version (0.1.0) is not newer than the current one (0.2.3)")
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected the binary to be untouched, got: %s", result)
	}
}

func TestApplySelfUpdateSkipsWhenHttpsRequiredAndUrlIsHttp(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  "irrelevant-not-reached",
			},
		},
	})

	downloadCalled := false
	fakeDownload := func(url, token string) ([]byte, error) { downloadCalled = true; return nil, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "http://example.invalid/download", "test-token", "0.2.3", true, false, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	if downloadCalled {
		t.Errorf("expected download to be skipped when requireHTTPS is true and the download URL is http")
	}
}

func TestApplySelfUpdateSkipsWhenSignatureRequiredAndMissing(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("new-binary-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])
	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
			},
		},
	})

	fakeDownload := func(url, token string) ([]byte, error) { return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.2.3", false, true, fakeDownload, fakeVerify, fakeIsRoot, "", 0); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected the binary to be untouched when a signature is required but none was advertised, got: %s", result)
	}
}

func TestApplySelfUpdateAppliesWithValidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("new-binary-content-with-a-real-signature")
	sum := sha256.Sum256(newContent)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign test payload: %v", err)
	}
	newHash := hex.EncodeToString(sum[:])

	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
				"sig":     base64.StdEncoding.EncodeToString(signature),
			},
		},
	})

	fakeDownload := func(url, token string) ([]byte, error) { return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }
	modulusBase64 := base64.StdEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.2.3", false, true, fakeDownload, fakeVerify, fakeIsRoot, modulusBase64, privateKey.PublicKey.E); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read swapped binary: %v", err)
	}
	if string(result) != string(newContent) {
		t.Errorf("expected the binary to be swapped when a genuinely valid signature is provided, got: %s", result)
	}
}

func TestApplySelfUpdateSkipsWithInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "wil-linux-client")
	oldContent := []byte("old-binary-content")
	if err := os.WriteFile(binaryPath, oldContent, 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	newContent := []byte("new-binary-content")
	sum := sha256.Sum256(newContent)
	newHash := hex.EncodeToString(sum[:])
	body, _ := json.Marshal(map[string]interface{}{
		"config": map[string]interface{}{
			"update": map[string]interface{}{
				"version": "9.9.9",
				"sha256":  newHash,
				"sig":     base64.StdEncoding.EncodeToString([]byte("not-a-real-signature")),
			},
		},
	})

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	modulusBase64 := base64.StdEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())

	fakeDownload := func(url, token string) ([]byte, error) { return newContent, nil }
	fakeVerify := func(path string) error { return nil }
	fakeIsRoot := func() bool { return true }

	if err := applySelfUpdate(body, binaryPath, "https://example.invalid/download", "test-token", "0.2.3", false, true, fakeDownload, fakeVerify, fakeIsRoot, modulusBase64, privateKey.PublicKey.E); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	result, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(result) != string(oldContent) {
		t.Errorf("expected the binary to be untouched when the advertised signature does not verify, got: %s", result)
	}
}

// TestSelfUpdatePublicKeyPlaceholderIsValidBase64 guards against exactly
// the class of bug Task 3's own review found on the Windows client: an
// invalid base64 placeholder constant that only fails the moment a real
// self-update actually tries to decode it. Every other test in this file
// calls the lowercase Core-level applySelfUpdate with its own
// independently-generated test key, so none of them would ever notice if
// the real pinned selfUpdatePublicKeyModulusBase64 constant were broken.
func TestSelfUpdatePublicKeyPlaceholderIsValidBase64(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(selfUpdatePublicKeyModulusBase64)
	if err != nil {
		t.Fatalf("selfUpdatePublicKeyModulusBase64 is not valid base64: %v", err)
	}
	if len(decoded) == 0 {
		t.Errorf("selfUpdatePublicKeyModulusBase64 decodes to zero bytes")
	}
}

// TestApplySelfUpdateRealEntryPointDoesNotPanicOnEmptyBody calls the real
// ApplySelfUpdate wrapper (capital-A, the one main.go actually calls) -
// every other test in this file calls only the lowercase testable
// applySelfUpdate Core function with its own injected key parameters,
// which would never exercise ApplySelfUpdate's own wiring of the real
// downloadClientPackage/verifyBinaryLaunches/isRunningAsRoot functions and
// the real pinned key constants. An empty response body is a deliberately
// trivial, deterministic case (no network, no root check reached) that
// still proves the real wrapper is callable and no-ops cleanly rather
// than panicking.
func TestApplySelfUpdateRealEntryPointDoesNotPanicOnEmptyBody(t *testing.T) {
	if err := ApplySelfUpdate(nil, "/nonexistent/wil-linux-client", "https://example.invalid/download", "test-token", "0.1.0", false, false); err != nil {
		t.Errorf("expected ApplySelfUpdate to no-op cleanly on an empty response body, got: %v", err)
	}
}
