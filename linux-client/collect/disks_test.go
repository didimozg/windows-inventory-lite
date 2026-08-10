package collect

import (
	"os"
	"path/filepath"
	"strings"
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

// noMountinfoPath points at a file that does not exist, so ParseBlockDevices
// falls back to its pre-mountinfo-filter behavior (report every /sys/block
// entry) - correct for tests that are only exercising size/type/model
// parsing, not the mount-based filter itself.
const noMountinfoPath = ""

func TestParseBlockDevicesSSD(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "sda", "size"), "1000215216\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "queue", "rotational"), "0\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "device", "model"), "Samsung SSD 970 EVO Plus 500GB\n")

	disks := ParseBlockDevices(root, noMountinfoPath)

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

	disks := ParseBlockDevices(root, noMountinfoPath)

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

	disks := ParseBlockDevices(root, noMountinfoPath)

	if len(disks) != 0 {
		t.Errorf("got %d disks, want 0 (device has no size file)", len(disks))
	}
}

// TestParseBlockDevicesFiltersToMountedDevicesOnly reproduces the real bug:
// inside an LXC container, /sys/block reflects the HOST's full device list
// (every other container's LVM volume, plus loop devices), not just the one
// device this container's root filesystem actually lives on. Confirmed live
// against a real Proxmox LXC container - /sys/block listed 16 dm-N volumes
// belonging to OTHER containers/VMs plus the host's own "sda", while
// /proc/self/mountinfo's root entry pointed at a single dm-N (major:minor
// 252:6, backed by /dev/mapper/pve-vm--103--disk--0) that was this
// container's own disk and no one else's.
func TestParseBlockDevicesFiltersToMountedDevicesOnly(t *testing.T) {
	root := t.TempDir()
	// This container's own disk - mounted, must be reported.
	writeFixtureFile(t, filepath.Join(root, "dm-6", "size"), "20971520\n")
	writeFixtureFile(t, filepath.Join(root, "dm-6", "dev"), "252:6\n")
	// Another container's LVM volume, visible in /sys/block only because
	// sysfs is not namespace-isolated for block devices under LXC - not
	// mounted here, must NOT be reported.
	writeFixtureFile(t, filepath.Join(root, "dm-7", "size"), "41943040\n")
	writeFixtureFile(t, filepath.Join(root, "dm-7", "dev"), "252:7\n")
	// The host's own physical disk, same story - not mounted in this
	// container, must NOT be reported.
	writeFixtureFile(t, filepath.Join(root, "sda", "size"), "1000215216\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "dev"), "8:0\n")

	mountinfoPath := filepath.Join(t.TempDir(), "mountinfo")
	mountinfoContent := strings.Join([]string{
		`566 355 252:6 / / rw,relatime shared:220 - ext4 /dev/mapper/pve-vm--103--disk--0 rw,stripe=16`,
		`567 566 0:65 / /dev rw,relatime shared:312 - tmpfs none rw,size=492k,mode=755`,
		`568 566 0:66 / /proc rw,nosuid,nodev,noexec,relatime shared:326 - proc proc rw`,
		`627 578 0:29 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:342 - cgroup2 none rw`,
	}, "\n") + "\n"
	writeFixtureFile(t, mountinfoPath, mountinfoContent)

	disks := ParseBlockDevices(root, mountinfoPath)

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1 (only the mounted dm-6): %+v", len(disks), disks)
	}
	if disks[0].SizeGb < 9 || disks[0].SizeGb > 11 {
		t.Errorf("SizeGb = %d, want ~10 (dm-6's size)", disks[0].SizeGb)
	}
}

// TestParseBlockDevicesDetectsDiskMountedViaPartition reproduces a real
// regression found on a Proxmox host: /sys/block only lists whole disks
// (e.g. "sdc"), but a disk that uses a traditional partition table is
// mounted via one of its PARTITIONS ("sdc1"), which has its own, different
// major:minor from the whole disk. The original mount-filter only ever
// compared the whole disk's own "dev" id against mountinfo, so any disk
// mounted through a partition (the common case - only a bare LVM/dm volume
// used directly, with no partition table, escaped this bug by coincidence)
// was wrongly treated as unmounted and dropped. Confirmed live: "sdc" (8:32)
// itself is never in mountinfo, only its partition "sdc1" (8:33) is, mounted
// at /mnt/pve/SSD.
func TestParseBlockDevicesDetectsDiskMountedViaPartition(t *testing.T) {
	root := t.TempDir()
	// Whole disk - never appears in mountinfo itself, only its partition does.
	writeFixtureFile(t, filepath.Join(root, "sdc", "size"), "1000215216\n")
	writeFixtureFile(t, filepath.Join(root, "sdc", "dev"), "8:32\n")
	// Its partition, expressed in sysfs as a subdirectory of the disk -
	// this is what's actually mounted.
	writeFixtureFile(t, filepath.Join(root, "sdc", "sdc1", "dev"), "8:33\n")
	// A disk with no mounted partition at all - must still be excluded.
	writeFixtureFile(t, filepath.Join(root, "sdb", "size"), "2952790016\n")
	writeFixtureFile(t, filepath.Join(root, "sdb", "dev"), "8:16\n")
	writeFixtureFile(t, filepath.Join(root, "sdb", "sdb1", "dev"), "8:17\n")

	mountinfoPath := filepath.Join(t.TempDir(), "mountinfo")
	mountinfoContent := strings.Join([]string{
		`52 32 8:33 / /mnt/pve/SSD rw,relatime shared:45 - xfs /dev/sdc1 rw,inode64`,
		`567 566 0:65 / /dev rw,relatime shared:312 - tmpfs none rw,size=492k,mode=755`,
	}, "\n") + "\n"
	writeFixtureFile(t, mountinfoPath, mountinfoContent)

	disks := ParseBlockDevices(root, mountinfoPath)

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1 (only sdc, matched via its mounted partition sdc1): %+v", len(disks), disks)
	}
	if disks[0].SizeGb < 476 || disks[0].SizeGb > 478 {
		t.Errorf("SizeGb = %d, want ~477 (sdc's own size)", disks[0].SizeGb)
	}
}

// TestParseBlockDevicesFallsBackToAllDevicesWhenMountinfoUnavailable covers
// the case where mountinfo can't be read or parses to nothing useful (should
// never happen on a real Linux host, but a missing/unreadable mountinfo must
// not silently blank out an otherwise-working report on a normal server).
func TestParseBlockDevicesFallsBackToAllDevicesWhenMountinfoUnavailable(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "sda", "size"), "1000215216\n")
	writeFixtureFile(t, filepath.Join(root, "sda", "dev"), "8:0\n")

	disks := ParseBlockDevices(root, filepath.Join(t.TempDir(), "does-not-exist"))

	if len(disks) != 1 {
		t.Fatalf("got %d disks, want 1 (fallback to unfiltered when mountinfo is unavailable)", len(disks))
	}
}

func TestParseMountedMajorMinorsExcludesPseudoFilesystems(t *testing.T) {
	mountinfo := strings.Join([]string{
		`566 355 252:6 / / rw,relatime shared:220 - ext4 /dev/mapper/pve-vm--103--disk--0 rw,stripe=16`,
		`567 566 0:65 / /dev rw,relatime shared:312 - tmpfs none rw,size=492k,mode=755`,
		`568 566 0:66 / /proc rw,nosuid,nodev,noexec,relatime shared:326 - proc proc rw`,
		`578 566 0:67 / /sys ro,nosuid,nodev,noexec,relatime shared:339 - sysfs sysfs rw`,
	}, "\n") + "\n"

	ids := parseMountedMajorMinors(strings.NewReader(mountinfo))

	if len(ids) != 1 {
		t.Fatalf("got %d major:minor ids, want 1: %+v", len(ids), ids)
	}
	if !ids["252:6"] {
		t.Errorf("expected 252:6 (the ext4 mount) to be present, got %+v", ids)
	}
}

func TestParseMountedMajorMinorsEmptyWhenOnlyPseudoFilesystems(t *testing.T) {
	mountinfo := `568 566 0:66 / /proc rw,nosuid,nodev,noexec,relatime shared:326 - proc proc rw` + "\n"

	ids := parseMountedMajorMinors(strings.NewReader(mountinfo))

	if len(ids) != 0 {
		t.Errorf("got %d major:minor ids, want 0: %+v", len(ids), ids)
	}
}
