package collect

import (
	"strings"
	"testing"
)

func TestParseMemInfo(t *testing.T) {
	input := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
`
	got := ParseMemInfo(strings.NewReader(input))
	want := 16384000 / 1024

	if got != want {
		t.Errorf("ParseMemInfo() = %d, want %d", got, want)
	}
}

func TestParseMemInfoMissingMemTotalReturnsZero(t *testing.T) {
	got := ParseMemInfo(strings.NewReader("MemFree: 100 kB\n"))
	if got != 0 {
		t.Errorf("ParseMemInfo() = %d, want 0", got)
	}
}
