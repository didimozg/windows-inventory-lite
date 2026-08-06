package collect

import (
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	input := `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
`
	info := ParseOSRelease(strings.NewReader(input))

	if info.ID != "ubuntu" {
		t.Errorf("ID = %q, want %q", info.ID, "ubuntu")
	}
	if info.VersionID != "22.04" {
		t.Errorf("VersionID = %q, want %q", info.VersionID, "22.04")
	}
	if info.PrettyName != "Ubuntu 22.04.4 LTS" {
		t.Errorf("PrettyName = %q, want %q", info.PrettyName, "Ubuntu 22.04.4 LTS")
	}
}

func TestParseOSReleaseIgnoresUnknownKeysAndBlankLines(t *testing.T) {
	input := `ID=debian

HOME_URL="https://www.debian.org/"
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`
	info := ParseOSRelease(strings.NewReader(input))

	if info.ID != "debian" || info.VersionID != "12" || info.PrettyName != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("got %+v", info)
	}
}
