package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

// ParseServiceUnitsJSON parses `systemctl list-units --output=json`'s
// array shape into the two fields this client actually needs. Malformed
// input (including non-JSON) returns an empty slice rather than an error
// - the caller (ListRunningServiceUnits) treats a parse failure the same
// as "no running services found" rather than crashing the whole report.
func ParseServiceUnitsJSON(jsonOutput string) []RunningUnit {
	var raw []systemctlUnitJSON
	if err := json.Unmarshal([]byte(jsonOutput), &raw); err != nil {
		return []RunningUnit{}
	}
	units := make([]RunningUnit, 0, len(raw))
	for _, u := range raw {
		units = append(units, RunningUnit{Unit: u.Unit, Description: u.Description})
	}
	return units
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

// ListRunningServiceUnits execs `systemctl list-units --output=json` and
// returns the parsed running units - the shared first step used both by
// the full inventory pipeline (CollectRunningServices, below) and the
// lightweight status-only ping (see linux-client's BuildStatusReport,
// added in a later task).
func ListRunningServiceUnits() ([]RunningUnit, error) {
	output, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--output=json").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	return ParseServiceUnitsJSON(string(output)), nil
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

	services := []ServiceInfo{}
	for _, unit := range units {
		fragmentPath := ""
		if fragmentPathOutput, err := exec.Command("systemctl", "show", unit.Unit, "--property=FragmentPath", "--value").Output(); err == nil {
			fragmentPath = strings.TrimSpace(string(fragmentPathOutput))
		}

		ownerPackage := ""
		ownerFound := false
		if fragmentPath != "" {
			searchOutput, _ := exec.Command("dpkg", "-S", fragmentPath).CombinedOutput()
			ownerPackage, ownerFound = ParseDpkgSearchOutput(string(searchOutput))
		}

		if service, include := BuildServiceInfo(unit, ownerPackage, ownerFound, packages); include {
			services = append(services, service)
		}
	}
	return services, nil
}
