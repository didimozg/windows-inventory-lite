package collect

import (
	"strings"
	"testing"
)

func TestParseDpkgStatusIncludesOnlyInstalledPackages(t *testing.T) {
	input := `Package: bash
Status: install ok installed
Priority: required
Version: 5.1-6ubuntu1

Package: old-removed-package
Status: deinstall ok config-files
Version: 1.0-1

Package: coreutils
Status: install ok installed
Version: 8.32-4.1ubuntu1
`
	packages := ParseDpkgStatus(strings.NewReader(input))

	if len(packages) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(packages), packages)
	}
	if packages[0].Name != "bash" || packages[0].Version != "5.1-6ubuntu1" {
		t.Errorf("packages[0] = %+v", packages[0])
	}
	if packages[0].Priority != "required" {
		t.Errorf("packages[0].Priority = %q, want %q", packages[0].Priority, "required")
	}
	if packages[1].Name != "coreutils" || packages[1].Version != "8.32-4.1ubuntu1" {
		t.Errorf("packages[1] = %+v", packages[1])
	}
	if packages[1].Priority != "" {
		t.Errorf("packages[1].Priority = %q, want empty (coreutils' stanza above has no Priority: line)", packages[1].Priority)
	}
}

func TestParseDpkgStatusEmptyInput(t *testing.T) {
	packages := ParseDpkgStatus(strings.NewReader(""))
	if len(packages) != 0 {
		t.Errorf("got %d packages, want 0", len(packages))
	}
}
