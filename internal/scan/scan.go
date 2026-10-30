// Package scan statically inspects a Drupal repository for things that tie it
// to Acquia or Pantheon. It never makes network calls, never reads database
// dumps or secrets, and only reports file paths and line numbers by default.
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jtarleton/stagecoach-scan/internal/rules"
)

const maxReadBytes = 1 << 20 // skip files larger than 1 MiB for content rules

type Options struct {
	ShowSnippets bool     // include redacted source lines in evidence
	Runtime      *Runtime // optional output of drush stagecoach:inspect
	MaxEvidence  int      // per finding; 0 = default
	Version      string
}

type Evidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Note    string `json:"note,omitempty"`
}

type Finding struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Platform    string         `json:"platform"`
	Category    string         `json:"category"`
	Severity    rules.Severity `json:"severity"`
	EffortHours float64        `json:"effort_hours"`
	Fix         string         `json:"fix"`
	Evidence    []Evidence     `json:"evidence"`
	Truncated   int            `json:"evidence_truncated,omitempty"`

	modules      []string // Drupal module names behind composer evidence
	composerOnly bool     // fired from composer matchers only
}

type Facts struct {
	Docroot         string        `json:"docroot"`
	Platform        string        `json:"platform_guess"`
	DrupalCore      string        `json:"drupal_core,omitempty"`
	DrupalMajor     int           `json:"drupal_major,omitempty"`
	PHPRequired     string        `json:"php_required,omitempty"`
	PHPPlatform     string        `json:"php_platform,omitempty"`
	PantheonPHP     string        `json:"pantheon_php,omitempty"`
	ComposerJSON    bool          `json:"composer_json"`
	ComposerLock    bool          `json:"composer_lock"`
	Packages        int           `json:"packages"`
	CustomModules   []string      `json:"custom_modules"`
	CustomThemes    []string      `json:"custom_themes"`
	Sites           []string      `json:"sites"`
	ConfigSyncDir   string        `json:"config_sync_dir,omitempty"`
	FilesScanned    int           `json:"files_scanned"`
	CommittedUpload int           `json:"committed_upload_files"`
	Runtime         *RuntimeFacts `json:"runtime,omitempty"`
}

type Summary struct {
	Score      int     `json:"score"`
	Readiness  string  `json:"readiness"`
	Blockers   int     `json:"blockers"`
	Warnings   int     `json:"warnings"`
	Infos      int     `json:"infos"`
	EffortLow  float64 `json:"effort_hours_low"`
	EffortHigh float64 `json:"effort_hours_high"`
}

type Result struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	ScannedAt string    `json:"scanned_at"`
	Project   string    `json:"project"` // directory basename only, never the absolute path
	Facts     Facts     `json:"facts"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// repo is the in-memory view of the walked tree.
type repo struct {
	root     string
	docroot  string            // relative, "" for repo root
	paths    []string          // relative slash paths of files AND directories
	isDir    map[string]bool   // path -> directory?
	packages map[string]string // composer name -> version/constraint
	pkgSrc   map[string]string // composer name -> "composer.json" | "composer.lock"
	cache    map[string][]byte
}

// Run scans root against rs.
func Run(root string, rs []rules.Rule, opt Options) (*Result, error) {
	if opt.MaxEvidence <= 0 {
		opt.MaxEvidence = 15
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, &os.PathError{Op: "scan", Path: root, Err: fs.ErrNotExist}
	}

	r := &repo{root: abs, isDir: map[string]bool{}, packages: map[string]string{}, pkgSrc: map[string]string{}, cache: map[string][]byte{}}
	facts := Facts{CustomModules: []string{}, CustomThemes: []string{}, Sites: []string{}}

	composer := r.readComposer(&facts)
	r.docroot = detectDocroot(abs, composer)
	facts.Docroot = r.docroot
	if facts.Docroot == "" {
		facts.Docroot = "."
	}
	if err := r.walk(&facts); err != nil {
		return nil, err
	}
	r.collectFacts(&facts)

	var findings []Finding
	fired := map[string]bool{}
	suppress := map[string][]string{}
	for _, rule := range rs {
		if f, ok := r.apply(rule, opt); ok {
			findings = append(findings, f)
			fired[rule.ID] = true
			suppress[rule.ID] = rule.SuppressedBy
		}
	}
	kept := findings[:0]
	for _, f := range findings {
		drop := false
		for _, by := range suppress[f.ID] {
			drop = drop || fired[by]
		}
		if !drop {
			kept = append(kept, f)
		}
	}
	findings = kept
	if opt.Runtime != nil {
		opt.Runtime.index()
		findings = applyRuntime(opt.Runtime, findings)
		facts.Runtime = opt.Runtime.facts()
	}
	findings = append(findings, builtins(r, &facts)...)

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.ID < b.ID
	})
	facts.Platform = guessPlatform(findings)
	if facts.Runtime != nil && facts.Runtime.Platform != "" && facts.Runtime.Platform != "unknown" {
		facts.Platform = facts.Runtime.Platform // observed beats inferred
	}

	return &Result{
		Tool:      "stagecoach-scan",
		Version:   opt.Version,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Project:   filepath.Base(abs),
		Facts:     facts,
		Findings:  findings,
		Summary:   summarize(findings),
	}, nil
}

// ---------------------------------------------------------------- composer

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
	Config     struct {
		Platform map[string]any `json:"platform"`
	} `json:"config"`
	Extra struct {
		Scaffold struct {
			Locations map[string]string `json:"locations"`
		} `json:"drupal-scaffold"`
	} `json:"extra"`
}

type composerLock struct {
	Packages    []struct{ Name, Version string } `json:"packages"`
	PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
}

func (r *repo) readComposer(f *Facts) *composerJSON {
	var cj *composerJSON
	if b, err := os.ReadFile(filepath.Join(r.root, "composer.json")); err == nil {
		f.ComposerJSON = true
		cj = &composerJSON{}
		if json.Unmarshal(b, cj) == nil {
			for k, v := range cj.Require {
				r.packages[k], r.pkgSrc[k] = v, "composer.json"
			}
			for k, v := range cj.RequireDev {
				r.packages[k], r.pkgSrc[k] = v, "composer.json"
			}
			f.PHPRequired = cj.Require["php"]
			if v, ok := cj.Config.Platform["php"]; ok {
				f.PHPPlatform = toString(v)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(r.root, "composer.lock")); err == nil {
		f.ComposerLock = true
		var cl composerLock
		if json.Unmarshal(b, &cl) == nil {
			for _, p := range append(cl.Packages, cl.PackagesDev...) {
				r.packages[p.Name], r.pkgSrc[p.Name] = p.Version, "composer.lock" // lock wins over constraint
			}
		}
	}
	for k := range r.packages {
		if k != "php" && !strings.HasPrefix(k, "ext-") {
			f.Packages++
		}
	}
	return cj
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func detectDocroot(root string, cj *composerJSON) string {
	if cj != nil {
		if w := strings.Trim(cj.Extra.Scaffold.Locations["web-root"], "./"); w != "" {
			return w
		}
	}
	for _, d := range []string{"web", "docroot", "html", "public"} {
		if st, err := os.Stat(filepath.Join(root, d, "sites")); err == nil && st.IsDir() {
			return d
		}
	}
	return ""
}

// ---------------------------------------------------------------- walk

func (r *repo) join(parts ...string) string {
	if r.docroot == "" {
		return strings.Join(parts, "/")
	}
	return r.docroot + "/" + strings.Join(parts, "/")
}

var sensitiveName = regexp.MustCompile(`(?i)^\.env|\.(pem|key|crt|p12|pfx|sql|sql\.gz|sqlite)$|^id_(rsa|ed25519)`)

func (r *repo) walk(f *Facts) error {
	skip := map[string]bool{
		".git": true, "vendor": true, "node_modules": true,
		r.join("core"): true, r.join("libraries"): true,
		r.join("modules/contrib"): true, r.join("themes/contrib"): true, r.join("profiles/contrib"): true,
	}
	uploads := regexp.MustCompile("^" + regexp.QuoteMeta(r.join("sites")) + "/[^/]+/files$")

	return filepath.WalkDir(r.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		rel, _ := filepath.Rel(r.root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if skip[rel] || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			r.paths = append(r.paths, rel)
			r.isDir[rel] = true
			if uploads.MatchString(rel) {
				f.CommittedUpload += countFiles(p, 5000)
				return fs.SkipDir
			}
			return nil
		}
		if sensitiveName.MatchString(d.Name()) {
			return nil // never index secrets or dumps
		}
		r.paths = append(r.paths, rel)
		f.FilesScanned++
		return nil
	})
}

func countFiles(dir string, limit int) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
			if n >= limit {
				return fs.SkipAll
			}
		}
		return nil
	})
	return n
}

var coreVersionRe = regexp.MustCompile(`const VERSION = '([^']+)'`)
var d7VersionRe = regexp.MustCompile(`define\('VERSION', '([^']+)'\)`)
var pantheonPHPRe = regexp.MustCompile(`(?m)^\s*php_version\s*:\s*['"]?([0-9.]+)`)

func (r *repo) collectFacts(f *Facts) {
	core := r.packages["drupal/core"]
	if core == "" {
		core = r.packages["drupal/core-recommended"]
	}
	if core == "" {
		if m := coreVersionRe.FindSubmatch(r.read(r.join("core/lib/Drupal.php"))); m != nil {
			core = string(m[1])
		} else if m := d7VersionRe.FindSubmatch(r.read(r.join("includes/bootstrap.inc"))); m != nil {
			core = string(m[1])
		}
	}
	f.DrupalCore = strings.TrimPrefix(core, "v")
	if m := regexp.MustCompile(`(\d+)`).FindString(f.DrupalCore); m != "" {
		f.DrupalMajor, _ = strconv.Atoi(m)
	}
	if m := pantheonPHPRe.FindSubmatch(r.read("pantheon.yml")); m != nil {
		f.PantheonPHP = string(m[1])
	}

	modRe := regexp.MustCompile("^" + regexp.QuoteMeta(r.join("modules/custom")) + "/([^/]+)$")
	themeRe := regexp.MustCompile("^" + regexp.QuoteMeta(r.join("themes/custom")) + "/([^/]+)$")
	siteRe := regexp.MustCompile("^" + regexp.QuoteMeta(r.join("sites")) + "/([^/]+)/settings\\.php$")
	for _, p := range r.paths {
		if m := modRe.FindStringSubmatch(p); m != nil && r.isDir[p] {
			f.CustomModules = append(f.CustomModules, m[1])
		}
		if m := themeRe.FindStringSubmatch(p); m != nil && r.isDir[p] {
			f.CustomThemes = append(f.CustomThemes, m[1])
		}
		if m := siteRe.FindStringSubmatch(p); m != nil {
			f.Sites = append(f.Sites, m[1])
		}
		if f.ConfigSyncDir == "" && strings.HasSuffix(p, "/core.extension.yml") && !strings.Contains(p, "/config/install/") && !strings.Contains(p, "/config/optional/") {
			f.ConfigSyncDir = strings.TrimSuffix(p, "/core.extension.yml")
		}
	}
	sort.Strings(f.CustomModules)
	sort.Strings(f.CustomThemes)
	sort.Strings(f.Sites)
}

func (r *repo) read(rel string) []byte {
	if b, ok := r.cache[rel]; ok {
		return b
	}
	p := filepath.Join(r.root, filepath.FromSlash(rel))
	st, err := os.Stat(p)
	if err != nil || st.IsDir() || st.Size() > maxReadBytes || sensitiveName.MatchString(st.Name()) {
		r.cache[rel] = nil
		return nil
	}
	b, _ := os.ReadFile(p)
	r.cache[rel] = b
	return b
}

// ---------------------------------------------------------------- rules

func (r *repo) apply(rule rules.Rule, opt Options) (Finding, bool) {
	var ev []Evidence
	m := rule.Match

	if len(m.Files) > 0 {
		for _, p := range r.paths {
			if anyGlob(m.Files, p) {
				ev = append(ev, Evidence{Path: p})
			}
		}
	}
	var modules []string
	for _, name := range m.Composer {
		if v, ok := r.packages[name]; ok {
			if mod, ok := strings.CutPrefix(name, "drupal/"); ok {
				modules = append(modules, mod)
			}
			ev = append(ev, Evidence{Path: r.pkgSrc[name], Note: name + " " + v})
		}
	}
	if len(m.ComposerNone) > 0 && len(r.packages) > 0 {
		found := false
		for _, name := range m.ComposerNone {
			if _, ok := r.packages[name]; ok {
				found = true
				break
			}
		}
		if !found {
			ev = append(ev, Evidence{Path: "composer.json", Note: "none of: " + strings.Join(m.ComposerNone, ", ")})
		}
	}
	if c := m.Content; c != nil && c.Pattern != "" {
		re, err := regexp.Compile(c.Pattern)
		if err == nil {
			for _, p := range r.paths {
				if r.isDir[p] || !anyGlob(c.Paths, p) || anyGlob(c.Exclude, p) {
					continue
				}
				ev = append(ev, grep(r.read(p), p, re, opt.ShowSnippets)...)
			}
		}
	}
	if len(ev) == 0 {
		return Finding{}, false
	}
	f := Finding{
		modules:      modules,
		composerOnly: len(m.Files) == 0 && m.Content == nil && len(m.ComposerNone) == 0,
		ID:           rule.ID, Title: rule.Title, Platform: rule.Platform, Category: rule.Category,
		Severity: rule.Severity, EffortHours: rule.EffortHours, Fix: rule.Fix, Evidence: ev,
	}
	if len(f.Evidence) > opt.MaxEvidence {
		f.Truncated = len(f.Evidence) - opt.MaxEvidence
		f.Evidence = f.Evidence[:opt.MaxEvidence]
	}
	return f, true
}

func grep(b []byte, path string, re *regexp.Regexp, snippets bool) []Evidence {
	if len(b) == 0 || bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 { // skip binaries
		return nil
	}
	var out []Evidence
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), maxReadBytes)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if re.MatchString(line) {
			e := Evidence{Path: path, Line: n}
			if snippets {
				e.Snippet = Redact(line)
			}
			out = append(out, e)
		}
	}
	return out
}

var quoted = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)

// Redact masks every string literal on the line, so a snippet can show
// *where* something is configured without leaking hostnames or passwords.
// Short platform tokens (env var names, paths we match on) are kept.
func Redact(line string) string {
	line = strings.TrimSpace(line)
	line = quoted.ReplaceAllStringFunc(line, func(s string) string {
		inner := s[1 : len(s)-1]
		if safeLiteral.MatchString(inner) {
			return s
		}
		return string(s[0]) + "***" + string(s[0])
	})
	if len(line) > 160 {
		line = line[:157] + "..."
	}
	return line
}

var safeLiteral = regexp.MustCompile(`^(AH_[A-Z_]+|PANTHEON_[A-Z_]+|PRESSFLOW_SETTINGS|dev|test|stage|prod|live|file_private_path|file_public_path|)$`)

// ---------------------------------------------------------------- built-ins

func builtins(r *repo, f *Facts) []Finding {
	var out []Finding
	add := func(id, title string, sev rules.Severity, hours float64, fix string, ev ...Evidence) {
		out = append(out, Finding{ID: id, Title: title, Platform: "generic", Category: "core",
			Severity: sev, EffortHours: hours, Fix: fix, Evidence: ev})
	}

	switch {
	case f.DrupalMajor == 7:
		add("core.drupal7", "Drupal 7 codebase", rules.Blocker, 80,
			"Drupal 7 reached end of life in January 2025. Migrate to Drupal 10/11 before re-platforming.",
			Evidence{Path: r.join("includes/bootstrap.inc"), Note: "Drupal " + f.DrupalCore})
	case f.DrupalMajor > 0 && f.DrupalMajor < 10:
		add("core.unsupported", "Unsupported Drupal major version", rules.Blocker, 24,
			"Upgrade to a supported Drupal major version first. The Upgrade Status module lists what's blocking.",
			Evidence{Path: "composer.lock", Note: "drupal/core " + f.DrupalCore})
	}

	if f.DrupalMajor != 7 {
		if !f.ComposerJSON {
			add("core.no_composer", "Not a Composer-managed project", rules.Blocker, 16,
				"Convert to the drupal/recommended-project layout so the container build can run composer install.")
		} else if !f.ComposerLock {
			add("core.no_composer_lock", "composer.lock is not committed", rules.Blocker, 1,
				"Commit composer.lock so image builds are reproducible.", Evidence{Path: "composer.json"})
		}
		if f.ConfigSyncDir == "" && f.ComposerJSON {
			add("core.no_config_sync", "No exported configuration found", rules.Warning, 4,
				"Export config (drush config:export) and commit it. Without it, deploys depend on database state and promotions can't be repeated.")
		}
	}

	if n := len(f.Sites); n > 1 {
		ev := make([]Evidence, 0, n)
		for _, s := range f.Sites {
			ev = append(ev, Evidence{Path: r.join("sites", s, "settings.php")})
		}
		add("core.multisite", "Multisite installation ("+strconv.Itoa(n)+" sites)", rules.Warning, float64(4*(n-1)),
			"Each site needs its own database, files volume and hostname. Plan them as separate Stagecoach projects or one release with per-site config.", ev...)
	}

	if f.CommittedUpload > 20 {
		add("core.committed_uploads", "User-uploaded files committed to git", rules.Warning, 1,
			"Move sites/*/files out of the repo (to the files volume or S3) and add it to .gitignore. It bloats every image build.",
			Evidence{Path: r.join("sites/*/files"), Note: strconv.Itoa(f.CommittedUpload) + "+ files"})
	}
	return out
}

// ---------------------------------------------------------------- scoring

func guessPlatform(findings []Finding) string {
	score := map[string]float64{}
	for _, f := range findings {
		if f.Platform == "acquia" || f.Platform == "pantheon" {
			score[f.Platform] += float64(f.Severity.Rank())
		}
	}
	switch {
	case score["acquia"] == 0 && score["pantheon"] == 0:
		return "unknown"
	case score["acquia"] > 0 && score["pantheon"] > 0 && math.Abs(score["acquia"]-score["pantheon"]) < 2:
		return "mixed"
	case score["acquia"] > score["pantheon"]:
		return "acquia"
	default:
		return "pantheon"
	}
}

// baseEffort covers work every migration needs regardless of findings:
// Dockerfile + settings.stagecoach.php, cluster provisioning, DB/files copy, cutover.
const baseEffort = 8

func summarize(findings []Finding) Summary {
	s := Summary{Score: 100}
	hours := float64(baseEffort)
	for _, f := range findings {
		hours += f.EffortHours
		switch f.Severity {
		case rules.Blocker:
			s.Blockers++
			s.Score -= 15
		case rules.Warning:
			s.Warnings++
			s.Score -= 5
		default:
			s.Infos++
		}
	}
	if s.Score < 0 {
		s.Score = 0
	}
	switch {
	case s.Score >= 80 && s.Blockers == 0:
		s.Readiness = "Ready"
	case s.Score >= 50:
		s.Readiness = "Needs work"
	default:
		s.Readiness = "Significant work"
	}
	s.EffortLow = math.Round(hours * 0.75)
	s.EffortHigh = math.Round(hours * 1.5)
	return s
}
