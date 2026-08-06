package collect

import (
	"bufio"
	"io"
	"strings"
)

type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

// ParseCPUInfo parses /proc/cpuinfo content. Cores is the count of
// "processor" entries (one per logical core - the standard Linux
// /proc/cpuinfo layout); Model is the first "model name" value found
// (repeated identically once per core on real hardware, so only the first
// is kept).
func ParseCPUInfo(r io.Reader) CPUInfo {
	info := CPUInfo{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "processor" {
			info.Cores++
		} else if key == "model name" && info.Model == "" {
			info.Model = value
		}
	}
	return info
}
