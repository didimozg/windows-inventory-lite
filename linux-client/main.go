package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// IngestionTokenEnvVar is the environment variable the systemd units deliver
// the token through, via a mode-600 EnvironmentFile. Passing it as --token
// instead would put it on the process command line, readable from
// /proc/<pid>/cmdline by any local user on this host.
const IngestionTokenEnvVar = "WIL_INGESTION_TOKEN"

// TimerUnitPath, StatusTimerUnitPath, and EnvFilePath are the fixed
// filesystem locations install.sh (server-generated, see
// GenerateLinuxInstallScriptLines/GenerateSystemdEnvFileLines in
// WindowsInventoryLiteServer.cs) copies this client's own systemd units and
// token env file to on a managed host. There is no --install-path flag on
// this client to vary them - the server always installs to these exact
// paths, so ApplyConfigFromServer can rewrite them in place with no
// discovery step. EnvFilePath matches the server's own
// LinuxClientEnvFilePath constant exactly.
const (
	TimerUnitPath       = "/etc/systemd/system/wil-linux-client.timer"
	StatusTimerUnitPath = "/etc/systemd/system/wil-linux-client-status.timer"
	EnvFilePath         = "/etc/wil-linux-client.env"
)

// ResolveIngestionToken prefers the environment (how systemd-managed runs get
// it) and falls back to the --token flag (how a standalone/manual run gets
// it). Pure - the caller does the os.Getenv - so it is directly unit-testable.
func ResolveIngestionToken(envToken, flagToken string) string {
	if envToken != "" {
		return envToken
	}
	return flagToken
}

func main() {
	serverURL := flag.String("server-url", "", "Server inventory endpoint, e.g. https://server.example.local/api/v1/linux/inventory")
	token := flag.String("token", "", "Ingestion token for standalone runs; systemd-managed runs get it from the WIL_INGESTION_TOKEN environment variable instead")
	mode := flag.String("mode", "full", "Report mode: 'full' (complete inventory) or 'status' (lightweight running-services check)")
	showVersion := flag.Bool("version", false, "Print the client version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(ClientVersion)
		return
	}

	ingestionToken := ResolveIngestionToken(os.Getenv(IngestionTokenEnvVar), *token)

	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --server-url is required")
		os.Exit(1)
	}

	if *mode != "full" && *mode != "status" {
		fmt.Fprintln(os.Stderr, "Error: --mode must be 'full' or 'status'")
		os.Exit(1)
	}

	if *mode == "status" {
		statusReport, err := BuildStatusReport()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to collect service status: %v\n", err)
			os.Exit(1)
		}
		// Config refresh rides the main report only (see below) - the
		// status ping's response body is discarded.
		if _, err := SendReport(*serverURL, ingestionToken, statusReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to send status report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Status report sent: %s\n", statusReport.Hostname)
		return
	}

	report, err := BuildReport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to collect inventory: %v\n", err)
		os.Exit(1)
	}

	responseBody, err := SendReport(*serverURL, ingestionToken, report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to send report: %v\n", err)
		os.Exit(1)
	}

	if applyErr := ApplyConfigFromServer(responseBody, TimerUnitPath, StatusTimerUnitPath, EnvFilePath); applyErr != nil {
		// Never fail an already-accepted report over a best-effort
		// follow-up action - log and continue, matching this project's
		// established principle on both clients (see
		// WindowsInventoryLiteClient.cs's identical reasoning for
		// ApplyInventoryAckResponse).
		log.Printf("config refresh failed (report already accepted): %v", applyErr)
	}

	// os.Args[0] is the real installed binary path here, not a relative or
	// symlinked one: the server always generates ExecStart= with the
	// absolute installDirectory path (GenerateSystemdUnitLines in
	// WindowsInventoryLiteServer.cs, e.g.
	// "/opt/windows-inventory-lite/wil-linux-client"), install.sh copies
	// the binary straight to that path with no symlink involved, and
	// systemd execs ExecStart directly (no shell, no PATH lookup), so
	// argv[0] as seen by this process is byte-for-byte that same absolute
	// path.
	if selfUpdateErr := ApplySelfUpdate(responseBody, os.Args[0], downloadURLFromServerURL(*serverURL), ingestionToken); selfUpdateErr != nil {
		log.Printf("self-update failed (report already accepted): %v", selfUpdateErr)
	}

	fmt.Printf("Report sent: %s\n", report.Hostname)
}

// downloadURLFromServerURL derives the self-update package download
// endpoint from the main inventory endpoint - mirrors config.go's own
// suffix-swap style, but for the Linux download endpoint added in Task 3
// (DownloadLinuxClientPackageUpdate, served at
// /api/v1/linux-client-package/update-download in
// WindowsInventoryLiteServer.cs).
func downloadURLFromServerURL(serverURL string) string {
	const inventorySuffix = "/api/v1/linux/inventory"
	if strings.HasSuffix(serverURL, inventorySuffix) {
		return serverURL[:len(serverURL)-len(inventorySuffix)] + "/api/v1/linux-client-package/update-download"
	}
	return serverURL
}
