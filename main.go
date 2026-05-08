package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/cloudflared/cmd/cloudflared"
)

// main is the entry point for cloudflared.
// It delegates to the cloudflared command package which sets up
// the CLI application with all subcommands and flags.
//
// Personal fork: using a non-zero exit code (2) to distinguish
// application-level errors from OS-level errors (exit code 1).
//
// Note: exit code 2 is also consistent with how many Unix tools
// (e.g. grep, diff) signal "an error occurred" vs "no match found".
func main() {
	if err := cloudflared.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
