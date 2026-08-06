package collect

import (
	"strings"
	"testing"
)

func TestParseCPUInfoSingleCore(t *testing.T) {
	input := `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i5-12400 CPU @ 2.50GHz
cpu MHz		: 2500.000
`
	info := ParseCPUInfo(strings.NewReader(input))

	if info.Cores != 1 {
		t.Errorf("Cores = %d, want 1", info.Cores)
	}
	if info.Model != "Intel(R) Core(TM) i5-12400 CPU @ 2.50GHz" {
		t.Errorf("Model = %q", info.Model)
	}
}

func TestParseCPUInfoMultiCoreCountsEachProcessorBlock(t *testing.T) {
	input := `processor	: 0
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz

processor	: 1
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz

processor	: 2
model name	: Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
`
	info := ParseCPUInfo(strings.NewReader(input))

	if info.Cores != 3 {
		t.Errorf("Cores = %d, want 3", info.Cores)
	}
	if info.Model != "Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz" {
		t.Errorf("Model = %q", info.Model)
	}
}
