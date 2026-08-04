package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	serverURL := flag.String("server-url", "", "Server inventory endpoint, e.g. https://server.example.local/api/v1/linux/inventory")
	token := flag.String("token", "", "Ingestion token (optional, must match the server's configured Token)")
	mode := flag.String("mode", "full", "Report mode: 'full' (complete inventory) or 'status' (lightweight running-services check)")
	showVersion := flag.Bool("version", false, "Print the client version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(ClientVersion)
		return
	}

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
		if err := SendReport(*serverURL, *token, statusReport); err != nil {
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

	if err := SendReport(*serverURL, *token, report); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to send report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Report sent: %s\n", report.Hostname)
}
