package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

type RunningUnit struct {
	Unit        string
	Description string
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Unit    string `json:"unit"`
	Version string `json:"version"`
	Active  bool   `json:"active"`
}

type systemctlUnitJSON struct {
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// ParseServiceUnitsJSON parses `systemctl list-units --output=json`'s array
// shape into the two fields this client actually needs.
//
// A genuine parse failure returns an error, deliberately distinct from a
// successfully-parsed empty array. The two are NOT interchangeable: in
// --mode=status an empty result becomes an empty activeUnits array, which the
// server's merge endpoint interprets as "every known service on this host just
// stopped" - so silently turning a malformed systemctl response into an empty
// slice manufactures a false total-outage alarm. Callers must treat the error
// as "don't send this ping", not as "nothing is running".
func ParseServiceUnitsJSON(jsonOutput string) ([]RunningUnit, error) {
	var raw []systemctlUnitJSON
	if err := json.Unmarshal([]byte(jsonOutput), &raw); err != nil {
		return nil, fmt.Errorf("parse systemctl list-units JSON: %w", err)
	}
	units := make([]RunningUnit, 0, len(raw))
	for _, u := range raw {
		units = append(units, RunningUnit{Unit: u.Unit, Description: u.Description})
	}
	return units, nil
}

// ParseDpkgSearchOutput parses `dpkg -S <path>`'s output. On success it
// looks like "packagename: /path/to/file" (or "pkg1, pkg2: /path" if
// multiple packages claim the same file - the first listed package is
// used, which is good enough for a systemd unit file, effectively never
// shared between packages in practice). On failure (no owning package)
// dpkg prints a "no path found matching pattern" message instead - ok is
// false in that case, and for any other unrecognized output shape.
func ParseDpkgSearchOutput(output string) (packageName string, ok bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, "no path found matching pattern") {
		return "", false
	}
	colonIndex := strings.Index(trimmed, ":")
	if colonIndex <= 0 {
		return "", false
	}
	namesPart := trimmed[:colonIndex]
	firstName := strings.TrimSpace(strings.Split(namesPart, ",")[0])
	if firstName == "" {
		return "", false
	}
	return firstName, true
}

// ParseDpkgSearchBatchOutput parses the output of ONE `dpkg -S path1 path2 ...`
// invocation covering many paths at once. Success lines look like
// "packagename: /path/to/file"; unowned paths produce a "no path found matching
// pattern" line instead, which is skipped rather than recorded.
//
// The map is keyed on the unit file's BASE NAME, not the full path: dpkg echoes
// the path as recorded in its own database, which on a usr-merged Debian/Ubuntu
// host is frequently /lib/systemd/system/x.service even when the query used
// /usr/lib/systemd/system/x.service. Keying on the full path would silently miss
// on exactly those hosts. Unit file base names are unique in practice.
//
// Pure - no I/O - directly unit-testable, same as its single-path sibling above.
func ParseDpkgSearchBatchOutput(output string) map[string]string {
	owners := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		packageName, reportedPath, ok := parseDpkgSearchLine(line)
		if !ok {
			continue
		}
		owners[path.Base(reportedPath)] = packageName
	}
	return owners
}

func parseDpkgSearchLine(line string) (packageName string, reportedPath string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.Contains(trimmed, "no path found matching pattern") {
		return "", "", false
	}
	colonIndex := strings.Index(trimmed, ":")
	if colonIndex <= 0 {
		return "", "", false
	}
	namesPart := trimmed[:colonIndex]
	pathPart := strings.TrimSpace(trimmed[colonIndex+1:])
	if pathPart == "" {
		return "", "", false
	}
	firstName := strings.TrimSpace(strings.Split(namesPart, ",")[0])
	if firstName == "" {
		return "", "", false
	}
	return firstName, pathPart, true
}

// basePriorities are dpkg's own Priority: classification for "part of
// the base system." A running service whose owning package carries one
// of these is filtered out as OS noise; optional/extra packages (or no
// owning package at all) are kept - a service with no owning dpkg
// package is exactly the kind of self-managed software (a hand-built
// binary, a custom container unit) an admin most wants visibility into,
// not noise to hide.
var basePriorities = map[string]bool{
	"required":  true,
	"important": true,
	"standard":  true,
}

// BuildServiceInfo decides whether a running unit should be reported and,
// if so, builds its ServiceInfo. Pure - no I/O - all resolution (owning
// package lookup via systemctl/dpkg) happens in the caller, CollectRunningServices.
func BuildServiceInfo(unit RunningUnit, ownerPackage string, ownerFound bool, packages map[string]PackageInfo) (ServiceInfo, bool) {
	if ownerFound {
		if pkg, known := packages[ownerPackage]; known && basePriorities[pkg.Priority] {
			return ServiceInfo{}, false
		}
	}

	name := strings.TrimSpace(unit.Description)
	if name == "" {
		name = strings.TrimSuffix(unit.Unit, ".service")
	}

	version := ""
	if ownerFound {
		if pkg, known := packages[ownerPackage]; known {
			version = pkg.Version
		}
	}

	return ServiceInfo{
		Name:    name,
		Unit:    unit.Unit,
		Version: version,
		Active:  true,
	}, true
}

// SystemctlPath and DpkgPath are absolute on purpose. This client runs as root
// under systemd with no User= line, and Debian/Ubuntu's default PATH for root
// services puts the group-writable /usr/local/bin ahead of /usr/bin - so a bare
// "systemctl"/"dpkg" resolved through PATH is a local privilege-escalation
// vector (anyone in the staff group can plant a fake one). Assumes these live at
// these paths on Debian/Ubuntu, this project's stated target distros.
const (
	SystemctlPath = "/usr/bin/systemctl"
	DpkgPath      = "/usr/bin/dpkg"
)

// ListRunningServiceUnits execs systemctl list-units and returns the parsed
// running units - the shared first step used both by the full inventory
// pipeline (CollectRunningServices, below) and the lightweight status-only
// ping (BuildStatusReport). A parse failure is returned as an error rather
// than an empty list; see ParseServiceUnitsJSON for why that distinction
// matters.
func ListRunningServiceUnits() ([]RunningUnit, error) {
	output, err := exec.Command(SystemctlPath, "list-units", "--type=service", "--state=running", "--output=json").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	return ParseServiceUnitsJSON(string(output))
}

// CollectRunningServices returns the currently-running systemd services,
// filtered to exclude base-OS packages and enriched with each service's
// owning package version where one can be found. Exec-heavy (systemctl +
// dpkg per running service) - not unit tested itself, matches this
// project's own established pattern for I/O-heavy collectors (see
// BuildReport's own comment in report.go); the pure decision logic it
// calls (ParseServiceUnitsJSON, ParseDpkgSearchOutput, BuildServiceInfo)
// is fully covered in services_test.go above.
func CollectRunningServices() ([]ServiceInfo, error) {
	units, err := ListRunningServiceUnits()
	if err != nil {
		return nil, err
	}

	dpkgStatusFile, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil, fmt.Errorf("open /var/lib/dpkg/status: %w", err)
	}
	defer dpkgStatusFile.Close()
	packageList := ParseDpkgStatus(dpkgStatusFile)
	packages := make(map[string]PackageInfo, len(packageList))
	for _, p := range packageList {
		packages[p.Name] = p
	}

	// Phase 1: resolve every unit's fragment path (one systemctl show per unit -
	// unavoidable, systemctl show takes one unit at a time for --value output).
	fragmentPaths := make(map[string]string, len(units))
	for _, unit := range units {
		if fragmentPathOutput, err := exec.Command(SystemctlPath, "show", unit.Unit, "--property=FragmentPath", "--value").Output(); err == nil {
			if trimmed := strings.TrimSpace(string(fragmentPathOutput)); trimmed != "" {
				fragmentPaths[unit.Unit] = trimmed
			}
		}
	}

	// Phase 2: one batched dpkg -S for ALL of those paths instead of one per
	// unit. dpkg -S accepts many path arguments in a single invocation, which
	// halves the process spawns for this collector - on a host with 40-60 running
	// units the old per-unit pair was 80-120 spawns, plausibly minutes, against
	// systemd's default 90s start timeout.
	owners := map[string]string{}
	if len(fragmentPaths) > 0 {
		args := make([]string, 0, len(fragmentPaths)+1)
		args = append(args, "-S")
		for _, fragmentPath := range fragmentPaths {
			args = append(args, fragmentPath)
		}
		// Exit status is deliberately ignored: dpkg -S exits non-zero when ANY of
		// the batched paths has no owning package, which is normal (a hand-built
		// service is exactly what this collector most wants to surface). The
		// per-path result is read from the output instead.
		searchOutput, _ := exec.Command(DpkgPath, args...).CombinedOutput()
		owners = ParseDpkgSearchBatchOutput(string(searchOutput))
	}

	services := []ServiceInfo{}
	for _, unit := range units {
		ownerPackage := ""
		ownerFound := false
		if fragmentPath, hasPath := fragmentPaths[unit.Unit]; hasPath {
			ownerPackage, ownerFound = owners[path.Base(fragmentPath)]
		}

		if service, include := BuildServiceInfo(unit, ownerPackage, ownerFound, packages); include {
			services = append(services, service)
		}
	}
	return services, nil
}
