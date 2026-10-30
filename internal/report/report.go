// Package report renders a scan.Result as text, JSON or a self-contained HTML page.
package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/jtarleton/stagecoach-scan/internal/rules"
	"github.com/jtarleton/stagecoach-scan/internal/scan"
)

func JSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// ---------------------------------------------------------------- text

type palette struct{ red, yellow, blue, green, dim, bold, reset string }

func Text(w io.Writer, r *scan.Result, color bool) error {
	c := palette{}
	if color {
		c = palette{"\033[31m", "\033[33m", "\033[36m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"}
	}
	sevColor := map[rules.Severity]string{rules.Blocker: c.red, rules.Warning: c.yellow, rules.Info: c.blue}
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	f, s := r.Facts, r.Summary
	p("%sStagecoach migration readiness: %s%s\n", c.bold, r.Project, c.reset)
	p("%s%s %s · scanned %s%s\n\n", c.dim, r.Tool, r.Version, r.ScannedAt, c.reset)

	scoreColor := c.green
	if s.Blockers > 0 || s.Score < 50 {
		scoreColor = c.red
	} else if s.Score < 80 {
		scoreColor = c.yellow
	}
	p("  Score       %s%s%d/100 · %s%s\n", c.bold, scoreColor, s.Score, s.Readiness, c.reset)
	p("  Findings    %s%d blocker(s)%s, %s%d warning(s)%s, %d info\n",
		c.red, s.Blockers, c.reset, c.yellow, s.Warnings, c.reset, s.Infos)
	p("  Effort      ~%.0f–%.0f hours (rough, includes containerize + cutover)\n\n", s.EffortLow, s.EffortHigh)

	p("  Platform    %s\n", f.Platform)
	p("  Drupal      %s\n", orDash(f.DrupalCore))
	p("  PHP         %s\n", orDash(join(", ", label("composer", f.PHPRequired), label("platform", f.PHPPlatform), label("pantheon.yml", f.PantheonPHP))))
	p("  Docroot     %s\n", f.Docroot)
	p("  Packages    %d (composer.lock: %s)\n", f.Packages, yesNo(f.ComposerLock))
	p("  Custom      %d module(s), %d theme(s)\n", len(f.CustomModules), len(f.CustomThemes))
	p("  Sites       %s\n", orDash(strings.Join(f.Sites, ", ")))
	p("  Config sync %s\n\n", orDash(f.ConfigSyncDir))

	if rt := f.Runtime; rt != nil {
		p("%sRuntime (from drush stagecoach:inspect)%s\n", c.bold, c.reset)
		p("  Environment %s\n", orDash(join(" / ", rt.Platform, rt.Env)))
		p("  PHP         %s\n", orDash(rt.PHP))
		p("  Database    %s · %.0f MB (%.0f MB to transfer, excl. cache tables)\n", orDash(rt.Database), rt.DBSizeMB, rt.DBTransferMB)
		p("  Files       %d managed · %.0f MB\n", rt.FilesCount, rt.FilesMB)
		p("  Modules     %d enabled (%d custom)\n", rt.EnabledModules, rt.CustomEnabled)
		p("  Cache       %s\n", orDash(rt.CacheBackend))
		p("  Search      %s\n", orDash(strings.Join(rt.SearchBackends, ", ")))
		p("  Mail        %s\n", orDash(rt.MailInterface))
		p("  Dockerfile  PHP extensions: %s\n", orDash(strings.Join(rt.DockerExtensions, " ")))
		if len(rt.CollectorErrors) > 0 {
			p("  %sCollector errors: %s%s\n", c.yellow, strings.Join(rt.CollectorErrors, "; "), c.reset)
		}
		p("\n")
	}

	if len(r.Findings) == 0 {
		p("%sNo platform lock-in found.%s\n", c.green, c.reset)
		return nil
	}
	for _, fd := range r.Findings {
		p("%s%-8s%s %s%s%s  %s[%s · ~%gh]%s\n", sevColor[fd.Severity], strings.ToUpper(string(fd.Severity)), c.reset,
			c.bold, fd.Title, c.reset, c.dim, fd.ID, fd.EffortHours, c.reset)
		p("         → %s\n", fd.Fix)
		for _, e := range fd.Evidence {
			p("         %s%s%s\n", c.dim, evidenceLine(e), c.reset)
		}
		if fd.Truncated > 0 {
			p("         %s… and %d more%s\n", c.dim, fd.Truncated, c.reset)
		}
		p("\n")
	}
	p("%sScanned locally; nothing left this machine. Use --format json or --format html for a shareable report.%s\n", c.dim, c.reset)
	return nil
}

func evidenceLine(e scan.Evidence) string {
	s := e.Path
	if e.Line > 0 {
		s += fmt.Sprintf(":%d", e.Line)
	}
	if e.Note != "" {
		s += "  (" + e.Note + ")"
	}
	if e.Snippet != "" {
		s += "  " + e.Snippet
	}
	return s
}

func label(k, v string) string {
	if v == "" {
		return ""
	}
	return k + " " + v
}

func join(sep string, parts ...string) string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---------------------------------------------------------------- html

//go:embed report.html.tmpl
var htmlTmpl string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":    func(s rules.Severity) string { return strings.ToUpper(string(s)) },
	"evidence": evidenceLine,
	"orDash":   orDash,
	"yesNo":    yesNo,
	"joinList": func(xs []string) string { return orDash(strings.Join(xs, ", ")) },
	"php": func(f scan.Facts) string {
		return orDash(join(" · ", label("composer", f.PHPRequired), label("platform", f.PHPPlatform), label("pantheon.yml", f.PantheonPHP)))
	},
	"tone": func(s scan.Summary) string {
		switch {
		case s.Blockers > 0 || s.Score < 50:
			return "bad"
		case s.Score < 80:
			return "warn"
		}
		return "good"
	},
}).Parse(htmlTmpl))

func HTML(w io.Writer, r *scan.Result) error {
	return tmpl.Execute(w, r)
}
