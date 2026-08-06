package collect

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// ParseMemInfo parses /proc/meminfo content and returns total RAM in
// megabytes, rounded down. /proc/meminfo reports MemTotal in kB. Returns 0
// if MemTotal is missing or unparseable.
func ParseMemInfo(r io.Reader) int {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
}
