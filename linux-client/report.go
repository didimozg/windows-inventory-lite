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

	disks := collect.ParseBlockDevices("/sys/block", "/proc/self/mountinfo")

	// Best-effort, matching every other collector in this file: a failure here
	// degrades to an empty Services list rather than throwing away a perfectly
	// good OS/CPU/RAM/disk report. Reported on stderr so systemd's journal shows
	// why the list is empty.
	services, err := collect.CollectRunningServices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not collect running services, reporting without them: %v\n", err)
		services = []collect.ServiceInfo{}
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

// StatusReport is the lightweight counterpart to Report, sent on a much
// faster cadence (see BuildStatusReport). It carries only which systemd
// units are currently running - no OS/CPU/RAM/disk data, and no
// per-service package/version resolution (that stays on the full
// inventory's slower cadence). The server merges this into the existing
// per-host report rather than treating it as a full replacement - see
// the new /api/v1/linux/inventory/service-status endpoint added in a
// later task.
type StatusReport struct {
	Hostname      string   `json:"hostname"`
	ClientVersion string   `json:"clientVersion"`
	ActiveUnits   []string `json:"activeUnits"`
	CollectedAt   string   `json:"collectedAt"`
}

// BuildStatusReport is the lightweight counterpart to BuildReport: it
// only lists currently-running systemd unit names via
// collect.ListRunningServiceUnits, skipping OS/CPU/RAM/disk collection
// and the per-service package/version resolution BuildReport's full
// Services collection does. No unit test, same reasoning as BuildReport
// - it depends on a real systemctl, which doesn't exist on this Windows
// dev machine.
func BuildStatusReport() (StatusReport, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return StatusReport{}, fmt.Errorf("read hostname: %w", err)
	}

	// Deliberately NOT best-effort, unlike BuildReport's own services call: a
	// status ping carries nothing BUT the active-unit list, so sending an empty
	// one after a collection failure would tell the server every service on this
	// host just stopped. Failing here means main.go exits without sending, and
	// the next timer tick tries again.
	units, err := collect.ListRunningServiceUnits()
	if err != nil {
		return StatusReport{}, fmt.Errorf("list running services: %w", err)
	}

	activeUnits := make([]string, 0, len(units))
	for _, u := range units {
		activeUnits = append(activeUnits, u.Unit)
	}

	return StatusReport{
		Hostname:      hostname,
		ClientVersion: ClientVersion,
		ActiveUnits:   activeUnits,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// SendReport POSTs payload as JSON to serverURL. If token is non-empty,
// it is sent as X-Inventory-Token, the same header name/semantics the
// server's existing Windows ingestion path already uses. payload is
// `any` rather than the concrete Report type so this same function
// serves both the full inventory (Report) and the lightweight status
// ping (StatusReport) - it never inspects payload's fields directly,
// only json.Marshal's it, so widening the type is a pure simplification,
// not a behavior change for existing Report callers.
func SendReport(serverURL, token string, payload any) error {
	body, err := json.Marshal(payload)
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
