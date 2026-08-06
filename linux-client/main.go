package main

import (
	"flag"
	"fmt"
	"os"
)

// IngestionTokenEnvVar is the environment variable the systemd units deliver
// the token through, via a mode-600 EnvironmentFile. Passing it as --token
// instead would put it on the process command line, readable from
// /proc/<pid>/cmdline by any local user on this host.
const IngestionTokenEnvVar = "WIL_INGESTION_TOKEN"

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
		if err := SendReport(*serverURL, ingestionToken, statusReport); err != nil {
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

	if err := SendReport(*serverURL, ingestionToken, report); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to send report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Report sent: %s\n", report.Hostname)
}
