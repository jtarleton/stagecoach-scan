// stagecoach-scan checks a Drupal repo for Acquia / Pantheon lock-in and
// estimates the work needed to move it to self-hosted Kubernetes.
//
// It runs entirely offline on the developer's machine.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jtarleton/stagecoach-scan/internal/report"
	"github.com/jtarleton/stagecoach-scan/internal/rules"
	"github.com/jtarleton/stagecoach-scan/internal/scan"
)

// Set at build time: go build -ldflags "-X main.version=v0.1.0"
var version = "dev"

const usage = `stagecoach-scan: offline migration-readiness scanner for Drupal on Acquia / Pantheon

Usage:
  stagecoach-scan scan [flags] [path]   Scan a Drupal repository (default: .)
  stagecoach-scan rules [--rules file]  List the active rules
  stagecoach-scan version

Scan flags:
  --format text|json|html   Output format (default: text)
  --out FILE                Write the report to FILE instead of stdout
  --rules FILE              Extra/override rules (JSON, same schema as the built-ins)
  --runtime FILE            Merge runtime facts from: drush stagecoach:inspect > runtime.json
  --show-snippets           Include matched source lines (string literals redacted)
  --fail-on LEVEL           Exit 2 if any finding is at/above LEVEL: blocker|warning|info|none (default: none)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "rules":
		os.Exit(runRules(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("stagecoach-scan", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

func runScan(args []string) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	format := fl.String("format", "text", "")
	out := fl.String("out", "", "")
	rulesPath := fl.String("rules", "", "")
	snippets := fl.Bool("show-snippets", false, "")
	failOn := fl.String("fail-on", "none", "")
	runtimePath := fl.String("runtime", "", "")
	if err := fl.Parse(reorder(args)); err != nil {
		return 1
	}
	path := "."
	if fl.NArg() > 0 {
		path = fl.Arg(0)
	}

	rs, err := rules.Load(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		return 1
	}
	opts := scan.Options{ShowSnippets: *snippets, Version: version}
	if *runtimePath != "" {
		if opts.Runtime, err = scan.LoadRuntime(*runtimePath); err != nil {
			fmt.Fprintln(os.Stderr, "runtime:", err)
			return 1
		}
	}
	res, err := scan.Run(path, rs, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return 1
	}

	var w io.Writer = os.Stdout
	toTTY := isTTY(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer f.Close()
		w, toTTY = f, false
	}

	switch strings.ToLower(*format) {
	case "json":
		err = report.JSON(w, res)
	case "html":
		err = report.HTML(w, res)
	case "text":
		err = report.Text(w, res, toTTY && os.Getenv("NO_COLOR") == "")
	default:
		fmt.Fprintf(os.Stderr, "unknown --format %q\n", *format)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s (score %d/100, %s)\n", *out, res.Summary.Score, res.Summary.Readiness)
	}

	if threshold := rules.Severity(strings.ToLower(*failOn)); threshold != "none" {
		if threshold.Rank() == 0 {
			fmt.Fprintf(os.Stderr, "unknown --fail-on %q\n", *failOn)
			return 1
		}
		for _, f := range res.Findings {
			if f.Severity.Rank() >= threshold.Rank() {
				return 2
			}
		}
	}
	return 0
}

func runRules(args []string) int {
	fl := flag.NewFlagSet("rules", flag.ContinueOnError)
	rulesPath := fl.String("rules", "", "")
	if err := fl.Parse(args); err != nil {
		return 1
	}
	rs, err := rules.Load(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		return 1
	}
	for _, r := range rs {
		fmt.Printf("%-32s %-8s %-9s %s\n", r.ID, r.Platform, r.Severity, r.Title)
	}
	fmt.Printf("\n%d rules (plus built-in core checks: Drupal version, composer.lock, config sync, multisite, committed uploads)\n", len(rs))
	return 0
}

// reorder lets flags follow the path ("scan ./site --format html"),
// which Go's flag package doesn't allow on its own.
func reorder(args []string) []string {
	var flags, pos []string
	valued := map[string]bool{"--format": true, "-format": true, "--out": true, "-out": true,
		"--rules": true, "-rules": true, "--fail-on": true, "-fail-on": true,
		"--runtime": true, "-runtime": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if valued[a] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
