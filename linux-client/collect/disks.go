package collect

import (
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

// ParseBlockDevices reads a Linux /sys/block-style layout under root (pass
// "/sys/block" in production, a fixture directory in tests) and returns
// one DiskInfo per block device found. "size" holds 512-byte sector count;
// "queue/rotational" is "1" for HDD, "0" (or absent) for SSD;
// "device/model" holds the model string when present. A device without a
// readable "size" file is skipped entirely - some virtual/loop devices
// lack one, and skipping is safer than reporting an invented 0 GB disk.
func ParseBlockDevices(root string) []DiskInfo {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

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
