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

// ParseBlockDevices reads a Linux /sys/block-style layout under root (pass
// "/sys/block" in production, a fixture directory in tests) and returns one
// DiskInfo per block device that this host/container actually has something
// mounted on, per mountinfoPath (pass "/proc/self/mountinfo" in production).
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
// anywhere (a spare, unpartitioned drive) no longer appears in the report.
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

		if filterByMount {
			devId, err := os.ReadFile(filepath.Join(root, name, "dev"))
			if err != nil || !mountedIds[strings.TrimSpace(string(devId))] {
				continue
			}
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
