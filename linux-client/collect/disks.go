package collect

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type DiskInfo struct {
	Type   string `json:"type"`
	SizeGb int    `json:"sizeGb"`
	Model  string `json:"model"`
}

// parseMountedMajorMinors reads /proc/self/mountinfo-format content and
// returns the set of "major:minor" device identifiers that have something
// real mounted on them. Major 0 is always a pseudo-filesystem (tmpfs, proc,
// sysfs, cgroup2, devpts, fuse.lxcfs, mqueue, ramfs, ...) with no backing
// block device, so it's excluded - confirmed against a real container's
// mountinfo, where every pseudo-filesystem line reported "0:N" and the one
// genuine mount (ext4 on an LVM volume) reported "252:6".
func parseMountedMajorMinors(r io.Reader) map[string]bool {
	ids := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		majorMinor := fields[2]
		if strings.HasPrefix(majorMinor, "0:") {
			continue
		}
		ids[majorMinor] = true
	}
	return ids
}

// isDiskMounted reports whether the disk at root/name has something mounted
// on it, either directly (its own "dev" id) or via one of its partitions
// (sysfs represents each as a subdirectory of the disk, e.g.
// "sda/sda1/dev") - see ParseBlockDevices for why both must be checked.
func isDiskMounted(root, name string, mountedIds map[string]bool) bool {
	if devId, err := os.ReadFile(filepath.Join(root, name, "dev")); err == nil {
		if mountedIds[strings.TrimSpace(string(devId))] {
			return true
		}
	}

	entries, err := os.ReadDir(filepath.Join(root, name))
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		devId, err := os.ReadFile(filepath.Join(root, name, entry.Name(), "dev"))
		if err != nil {
			continue
		}
		if mountedIds[strings.TrimSpace(string(devId))] {
			return true
		}
	}
	return false
}

// ParseBlockDevices reads a Linux /sys/block-style layout under root (pass
// "/sys/block" in production, a fixture directory in tests) and returns one
// DiskInfo per block device that this host/container actually has something
// mounted on, per mountinfoPath (pass "/proc/self/mountinfo" in production).
// A disk counts as mounted if EITHER its own "dev" id is mounted (the case
// for a bare LVM/dm volume used directly, with no partition table) OR any of
// its partitions' "dev" id is mounted (the common case for a disk with a
// traditional partition table, e.g. "sda" mounted via "sda1") - /sys/block
// only ever lists whole disks, never partitions, but mountinfo records
// whichever device is actually mounted, which for a partitioned disk is the
// partition, not the disk itself. Missing this originally caused a real
// regression: on a Proxmox host, a disk ("sdc") whose only partition
// ("sdc1") was mounted at /mnt/pve/SSD was wrongly dropped from the report,
// because only the whole disk's own (never-mounted) id was being checked.
//
// The mount-based filter exists because /sys/block is not namespace-isolated
// under LXC: a container sees the block-device list of the whole physical
// host, including every OTHER container's and VM's LVM volumes - confirmed
// live against a real Proxmox LXC container, where /sys/block listed 16
// dm-N volumes belonging to other guests plus the host's own disk, while
// only ONE device (the container's own root filesystem) was actually
// mounted inside it. A bare-metal server or a full VM does not have this
// problem in practice - every disk that matters is normally mounted
// somewhere - so applying the same filter everywhere, rather than only
// inside detected containers, keeps this function's behavior uniform and
// avoids maintaining a separate container-detection code path. The one
// accepted trade-off: a physical disk that is inserted but never mounted
// anywhere, directly or through any partition (a spare, unpartitioned
// drive, or one used raw by e.g. ZFS/mdadm without ever appearing in
// mountinfo), no longer appears in the report.
//
// If mountinfoPath cannot be read or contains no real (non-pseudo-fs) mount
// at all, every /sys/block entry is reported unfiltered instead of silently
// returning zero disks - this should never happen on a real Linux host, but
// a missing/unreadable mountinfo must not blank out an otherwise-working
// report.
//
// "size" holds 512-byte sector count; "queue/rotational" is "1" for HDD,
// "0" (or absent) for SSD; "device/model" holds the model string when
// present. A device without a readable "size" file is skipped entirely -
// some virtual/loop devices lack one, and skipping is safer than reporting
// an invented 0 GB disk.
func ParseBlockDevices(root string, mountinfoPath string) []DiskInfo {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	mountedIds := map[string]bool{}
	if mountinfoFile, err := os.Open(mountinfoPath); err == nil {
		mountedIds = parseMountedMajorMinors(mountinfoFile)
		mountinfoFile.Close()
	}
	filterByMount := len(mountedIds) > 0

	disks := []DiskInfo{}
	for _, entry := range entries {
		name := entry.Name()
		sizeBytes, err := os.ReadFile(filepath.Join(root, name, "size"))
		if err != nil {
			continue
		}
		sectors, err := strconv.ParseInt(strings.TrimSpace(string(sizeBytes)), 10, 64)
		if err != nil {
			continue
		}

		if filterByMount && !isDiskMounted(root, name, mountedIds) {
			continue
		}

		disk := DiskInfo{
			Type:   "SSD",
			SizeGb: int(sectors * 512 / (1024 * 1024 * 1024)),
		}

		rotational, err := os.ReadFile(filepath.Join(root, name, "queue", "rotational"))
		if err == nil && strings.TrimSpace(string(rotational)) == "1" {
			disk.Type = "HDD"
		}

		model, err := os.ReadFile(filepath.Join(root, name, "device", "model"))
		if err == nil {
			disk.Model = strings.TrimSpace(string(model))
		}

		disks = append(disks, disk)
	}
	return disks
}
