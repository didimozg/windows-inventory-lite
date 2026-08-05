package collect

import "testing"

func TestParseServiceUnitsJSONExtractsUnitAndDescription(t *testing.T) {
	input := `[
  {"unit":"radarr.service","load":"loaded","active":"active","sub":"running","description":"Radarr","following":"","object_path":"/x","job_id":0,"job_type":"","job_path":"/y"},
  {"unit":"ssh.service","load":"loaded","active":"active","sub":"running","description":"OpenBSD Secure Shell server","following":"","object_path":"/z","job_id":0,"job_type":"","job_path":"/w"}
]`
	units, err := ParseServiceUnitsJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(units) != 2 {
		t.Fatalf("got %d units, want 2: %+v", len(units), units)
	}
	if units[0].Unit != "radarr.service" || units[0].Description != "Radarr" {
		t.Errorf("units[0] = %+v", units[0])
	}
	if units[1].Unit != "ssh.service" || units[1].Description != "OpenBSD Secure Shell server" {
		t.Errorf("units[1] = %+v", units[1])
	}
}

func TestParseServiceUnitsJSONEmptyArrayIsNotAnError(t *testing.T) {
	// A legitimately empty [] means "nothing is running" and must stay
	// distinguishable from a parse failure - the server treats an empty
	// activeUnits list as "every known service on this host just stopped".
	units, err := ParseServiceUnitsJSON("[]")
	if err != nil {
		t.Fatalf("an empty array is a valid answer, not an error: %v", err)
	}
	if len(units) != 0 {
		t.Errorf("got %d units, want 0", len(units))
	}
}

func TestParseServiceUnitsJSONMalformedInputReturnsError(t *testing.T) {
	// Previously this returned an empty slice, which in --mode=status became an
	// empty activeUnits array, which the server's merge endpoint reads as "every
	// known service on this host just stopped" - a total-outage alarm
	// manufactured from one malformed systemctl response.
	units, err := ParseServiceUnitsJSON("not json at all")
	if err == nil {
		t.Fatalf("expected an error for malformed input, got %d units", len(units))
	}
}

func TestParseServiceUnitsJSONTruncatedOutputReturnsError(t *testing.T) {
	// The realistic failure: systemctl's output gets cut off mid-array.
	_, err := ParseServiceUnitsJSON(`[{"unit":"radarr.service","description":"Rad`)
	if err == nil {
		t.Fatal("expected an error for truncated JSON")
	}
}

func TestParseDpkgSearchOutputSuccessSinglePackage(t *testing.T) {
	name, ok := ParseDpkgSearchOutput("radarr: /lib/systemd/system/radarr.service\n")
	if !ok {
		t.Fatal("expected ok=true for a valid dpkg -S success line")
	}
	if name != "radarr" {
		t.Errorf("got package name %q, want %q", name, "radarr")
	}
}

func TestParseDpkgSearchOutputSuccessMultiplePackagesUsesFirst(t *testing.T) {
	name, ok := ParseDpkgSearchOutput("pkg1, pkg2: /some/shared/path\n")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if name != "pkg1" {
		t.Errorf("got package name %q, want %q (the first listed)", name, "pkg1")
	}
}

func TestParseDpkgSearchOutputNoMatchReturnsNotOk(t *testing.T) {
	_, ok := ParseDpkgSearchOutput("dpkg-query: no path found matching pattern /custom/my-service.service\n")
	if ok {
		t.Fatal("expected ok=false when dpkg -S finds no owning package")
	}
}

func TestParseDpkgSearchOutputEmptyReturnsNotOk(t *testing.T) {
	_, ok := ParseDpkgSearchOutput("")
	if ok {
		t.Fatal("expected ok=false for empty output")
	}
}

func TestBuildServiceInfoExcludesBaseOsPackage(t *testing.T) {
	unit := RunningUnit{Unit: "ssh.service", Description: "OpenBSD Secure Shell server"}
	packages := map[string]PackageInfo{
		"openssh-server": {Name: "openssh-server", Version: "1:8.9p1-3", Priority: "important"},
	}
	_, include := BuildServiceInfo(unit, "openssh-server", true, packages)
	if include {
		t.Error("expected a service owned by an 'important'-priority package to be excluded")
	}
}

func TestBuildServiceInfoIncludesOptionalPriorityPackageWithVersion(t *testing.T) {
	unit := RunningUnit{Unit: "radarr.service", Description: "Radarr"}
	packages := map[string]PackageInfo{
		"radarr": {Name: "radarr", Version: "4.7.5.7809", Priority: "optional"},
	}
	service, include := BuildServiceInfo(unit, "radarr", true, packages)
	if !include {
		t.Fatal("expected a service owned by an 'optional'-priority package to be included")
	}
	if service.Name != "Radarr" || service.Unit != "radarr.service" || service.Version != "4.7.5.7809" {
		t.Errorf("service = %+v", service)
	}
	if !service.Active {
		t.Error("expected Active=true for a service collected as part of a full inventory run")
	}
}

func TestBuildServiceInfoIncludesServiceWithNoOwningPackage(t *testing.T) {
	unit := RunningUnit{Unit: "my-custom-app.service", Description: "My Custom App"}
	packages := map[string]PackageInfo{}
	service, include := BuildServiceInfo(unit, "", false, packages)
	if !include {
		t.Fatal("expected a service with no owning dpkg package to be included, not filtered as base-OS")
	}
	if service.Version != "" {
		t.Errorf("expected empty Version when no owning package was found, got %q", service.Version)
	}
}

func TestBuildServiceInfoFallsBackToUnitNameWhenDescriptionEmpty(t *testing.T) {
	unit := RunningUnit{Unit: "my-custom-app.service", Description: ""}
	service, include := BuildServiceInfo(unit, "", false, map[string]PackageInfo{})
	if !include {
		t.Fatal("expected inclusion")
	}
	if service.Name != "my-custom-app" {
		t.Errorf("got Name %q, want %q (unit name with .service stripped)", service.Name, "my-custom-app")
	}
}

func TestParseDpkgSearchBatchOutputMapsEachPathToItsPackage(t *testing.T) {
	output := "radarr: /lib/systemd/system/radarr.service\n" +
		"openssh-server: /lib/systemd/system/ssh.service\n" +
		"cron: /lib/systemd/system/cron.service\n"
	owners := ParseDpkgSearchBatchOutput(output)
	if len(owners) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(owners), owners)
	}
	if owners["radarr.service"] != "radarr" {
		t.Errorf("radarr.service -> %q, want %q", owners["radarr.service"], "radarr")
	}
	if owners["ssh.service"] != "openssh-server" {
		t.Errorf("ssh.service -> %q, want %q", owners["ssh.service"], "openssh-server")
	}
}

func TestParseDpkgSearchBatchOutputSkipsNotFoundLines(t *testing.T) {
	// One batched invocation mixes successes with dpkg-query's not-found
	// complaints for unowned units; the not-found lines must not become entries.
	output := "radarr: /lib/systemd/system/radarr.service\n" +
		"dpkg-query: no path found matching pattern /etc/systemd/system/my-custom.service\n"
	owners := ParseDpkgSearchBatchOutput(output)
	if len(owners) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(owners), owners)
	}
	if _, found := owners["my-custom.service"]; found {
		t.Error("a not-found line must not produce a map entry")
	}
}

func TestParseDpkgSearchBatchOutputUsesFirstPackageWhenSeveralClaimAPath(t *testing.T) {
	owners := ParseDpkgSearchBatchOutput("pkg1, pkg2: /lib/systemd/system/shared.service\n")
	if owners["shared.service"] != "pkg1" {
		t.Errorf("shared.service -> %q, want %q (the first listed)", owners["shared.service"], "pkg1")
	}
}

func TestParseDpkgSearchBatchOutputKeysOnBaseNameNotFullPath(t *testing.T) {
	// dpkg echoes the path as recorded in its database, which on a usr-merged
	// host is /lib/... even when the query used /usr/lib/... - so lookups key on
	// the unit file's base name.
	owners := ParseDpkgSearchBatchOutput("openssh-server: /lib/systemd/system/ssh.service\n")
	if owners["ssh.service"] != "openssh-server" {
		t.Errorf("expected the base name to be the key, got map %+v", owners)
	}
}

func TestParseDpkgSearchBatchOutputEmptyIsEmpty(t *testing.T) {
	owners := ParseDpkgSearchBatchOutput("")
	if len(owners) != 0 {
		t.Errorf("got %d entries, want 0", len(owners))
	}
}
