package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	serverURL := flag.String("server-url", "", "Server inventory endpoint, e.g. https://server.example.local/api/v1/linux/inventory")
	token := flag.String("token", "", "Ingestion token (optional, must match the server's configured Token)")
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
