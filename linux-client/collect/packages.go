package collect

import (
	"bufio"
	"io"
	"strings"
)

type PackageInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Priority string // dpkg's own classification (required/important/standard/optional/extra) - used internally by services.go's base-OS filter. Not JSON-tagged: PackageInfo no longer appears in the client's JSON report at all as of this task (see report.go's Services field replacing Packages).
}

// ParseDpkgStatus parses /var/lib/dpkg/status content: stanzas separated
// by blank lines, each describing one package's current state. Only
// stanzas with "Status: install ok installed" are included - dpkg's
// status file also lists packages that were removed-but-not-purged and
// others not currently installed, which a naive Package/Version-only
// parse would wrongly count as installed software.
func ParseDpkgStatus(r io.Reader) []PackageInfo {
	packages := []PackageInfo{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var name, version, status, priority string
	flush := func() {
		if name != "" && strings.Contains(status, "install ok installed") {
			packages = append(packages, PackageInfo{Name: name, Version: version, Priority: priority})
		}
		name, version, status, priority = "", "", "", ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		} else if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Status:") {
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		} else if strings.HasPrefix(line, "Priority:") {
			priority = strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))
		}
	}
	flush()

	return packages
}
