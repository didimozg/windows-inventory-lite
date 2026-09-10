package main

import (
	"crypto/sha256"
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

	if err := applySelfUpdate(body, binaryPath, "http://example.invalid/download", "test-token", fakeDownload, fakeVerify); err != nil {
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

	if err := applySelfUpdate(body, binaryPath, "http://example.invalid/download", "test-token", fakeDownload, fakeVerify); err != nil {
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

	if err := applySelfUpdate(body, binaryPath, "http://example.invalid/download", "test-token", fakeDownload, fakeVerify); err != nil {
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

	if err := applySelfUpdate(body, binaryPath, "http://example.invalid/download", "test-token", fakeDownload, fakeVerify); err != nil {
		t.Fatalf("applySelfUpdate returned error: %v", err)
	}
	if downloadCalled {
		t.Error("expected no download attempt when the response carries no update field")
	}
}
