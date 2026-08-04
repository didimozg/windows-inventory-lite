package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"windows-inventory-lite/linux-client/collect"
)

// ClientVersion is set at build time via -ldflags "-X main.ClientVersion=..."
// (see src/Build-LinuxClient.ps1). Defaults to "dev" for a plain `go build`
// with no ldflags. Independent of the Windows client's own version line -
// this client only moves its version when its own code/data changes.
var ClientVersion = "dev"

type Report struct {
	Hostname      string                `json:"hostname"`
	ClientVersion string                `json:"clientVersion"`
	OS            collect.OSInfo        `json:"os"`
	CPU           collect.CPUInfo       `json:"cpu"`
	RAMTotalMb    int                   `json:"ramTotalMb"`
	Disks         []collect.DiskInfo    `json:"disks"`
	IPAddresses   []string              `json:"ipAddresses"`
	Services      []collect.ServiceInfo `json:"services"`
	CollectedAt   string                `json:"collectedAt"`
}

// BuildReport gathers a full inventory snapshot from the real machine.
// No unit test - every field here comes from a real file under /proc,
// /sys, or /etc that only exists on a real Linux host; the pure parsing
// logic each field goes through is already covered in package collect's
// own tests. Verified live against the test fleet (Task 5), not here.
func BuildReport() (Report, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return Report{}, fmt.Errorf("read hostname: %w", err)
	}

	osReleaseFile, err := os.Open("/etc/os-release")
	if err != nil {
		return Report{}, fmt.Errorf("open /etc/os-release: %w", err)
	}
	defer osReleaseFile.Close()
	osInfo := collect.ParseOSRelease(osReleaseFile)

	cpuInfoFile, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return Report{}, fmt.Errorf("open /proc/cpuinfo: %w", err)
	}
	defer cpuInfoFile.Close()
	cpuInfo := collect.ParseCPUInfo(cpuInfoFile)

	memInfoFile, err := os.Open("/proc/meminfo")
	if err != nil {
		return Report{}, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer memInfoFile.Close()
	ramTotalMb := collect.ParseMemInfo(memInfoFile)

	disks := collect.ParseBlockDevices("/sys/block")

	services, err := collect.CollectRunningServices()
	if err != nil {
		return Report{}, fmt.Errorf("collect running services: %w", err)
	}

	return Report{
		Hostname:      hostname,
		ClientVersion: ClientVersion,
		OS:            osInfo,
		CPU:           cpuInfo,
		RAMTotalMb:    ramTotalMb,
		Disks:         disks,
		IPAddresses:   collect.CollectIPAddresses(),
		Services:      services,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// SendReport POSTs report as JSON to serverURL. If token is non-empty, it
// is sent as X-Inventory-Token, the same header name/semantics the
// server's existing Windows ingestion path already uses (the Linux
// ingestion endpoint reuses the server's one shared Token setting).
func SendReport(serverURL, token string, report Report) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, serverURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if token != "" {
		req.Header.Set("X-Inventory-Token", token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}
