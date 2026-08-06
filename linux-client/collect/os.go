package collect

import (
	"bufio"
	"io"
	"strings"
)

type OSInfo struct {
	ID         string `json:"id"`
	VersionID  string `json:"versionId"`
	PrettyName string `json:"prettyName"`
}

// ParseOSRelease parses /etc/os-release-formatted content (KEY=VALUE per
// line, values optionally double-quoted) and extracts ID, VERSION_ID, and
// PRETTY_NAME. Unknown keys and blank/comment lines are ignored.
func ParseOSRelease(r io.Reader) OSInfo {
	info := OSInfo{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], `"`)
		switch key {
		case "ID":
			info.ID = value
		case "VERSION_ID":
			info.VersionID = value
		case "PRETTY_NAME":
			info.PrettyName = value
		}
	}
	return info
}
