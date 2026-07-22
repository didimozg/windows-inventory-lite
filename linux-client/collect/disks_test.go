package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestParseBlockDevicesSSD(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "sda", "size"), "1000215216\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "queue", "rotational"), "0\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "device", "model"), "Samsung SSD 970 EVO Plus 500GB\n")

	disks := ParseBlockDevices(root)

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1", len(disks))
	}
	if disks[0].Type != "SSD" {
		t.Errorf("Type = %q, want SSD", disks[0].Type)
	}
	if disks[0].Model != "Samsung SSD 970 EVO Plus 500GB" {
		t.Errorf("Model = %q", disks[0].Model)
	}
	if disks[0].SizeGb < 476 || disks[0].SizeGb > 478 {
		t.Errorf("SizeGb = %d, want ~477", disks[0].SizeGb)
	}
}

func TestParseBlockDevicesHDD(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "sdb", "size"), "3907029168\n")
	writeFixtureFile(t, filepath.Join(root, "sdb", "queue", "rotational"), "1\n")

	disks := ParseBlockDevices(root)

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1", len(disks))
	}
	if disks[0].Type != "HDD" {
		t.Errorf("Type = %q, want HDD", disks[0].Type)
	}
	if disks[0].Model != "" {
		t.Errorf("Model = %q, want empty (no device/model file)", disks[0].Model)
	}
}

func TestParseBlockDevicesSkipsDeviceWithoutSizeFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop0"), 0755); err != nil {
		t.Fatal(err)
	}

	disks := ParseBlockDevices(root)

	if len(disks) != 0 {
		t.Errorf("got %d disks, want 0 (device has no size file)", len(disks))
	}
}
