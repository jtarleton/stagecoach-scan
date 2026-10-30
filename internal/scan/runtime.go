package scan

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jtarleton/stagecoach-scan/internal/rules"
)

// Runtime is the subset of `drush stagecoach:inspect` output the scanner uses.
// Unknown fields are ignored so the module can add facts without a CLI release.
type Runtime struct {
	Schema      string `json:"schema"`
	Environment struct {
		Platform string `json:"platform"`
		Env      string `json:"env"`
	} `json:"environment"`
	PHP struct {
		Version    string   `json:"version"`
		Extensions []string `json:"extensions"`
	} `json:"php"`
	Database struct {
		Driver        string   `json:"driver"`
		Version       string   `json:"version"`
		SizeMB        *float64 `json:"size_mb"`
		CacheTablesMB *float64 `json:"cache_tables_mb"`
		NonInnoDB     []struct {
			Name   string `json:"name"`
			Engine string `json:"engine"`
		} `json:"non_innodb_tables"`
	} `json:"database"`
	Modules struct {
		Count   int `json:"count"`
		Enabled []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"enabled"`
	} `json:"modules"`
	Files struct {
		PrivatePathSet bool `json:"private_path_set"`
		Managed        map[string]struct {
			Count  int     `json:"count"`
			SizeMB float64 `json:"size_mb"`
		} `json:"managed"`
	} `json:"files"`
	Cache struct {
		DefaultBackend string `json:"default_backend"`
	} `json:"cache"`
	Search struct {
		Servers []struct {
			ID        string `json:"id"`
			Backend   string `json:"backend"`
			Connector string `json:"connector"`
			Status    bool   `json:"status"`
		} `json:"servers"`
	} `json:"search"`
	Mail struct {
		DefaultInterface  string `json:"default_interface"`
		SymfonyMailer     bool   `json:"symfony_mailer"`
		SymfonyMailerLite bool   `json:"symfony_mailer_lite"`
		SMTP              bool   `json:"smtp"`
	} `json:"mail"`
	Cron struct {
		LastRun       *string `json:"last_run"`
		AutomatedCron bool    `json:"automated_cron"`
		UltimateCron  bool    `json:"ultimate_cron"`
	} `json:"cron"`
	Queues []struct {
		Name  string `json:"name"`
		Items int    `json:"items"`
	} `json:"queues"`
	Errors []string `json:"errors"`

	enabled map[string]bool
}

// LoadRuntime reads and validates a stagecoach:inspect JSON file.
func LoadRuntime(path string) (*Runtime, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rt Runtime
	if err := json.Unmarshal(b, &rt); err != nil {
		return nil, fmt.Errorf("%s: not valid JSON: %w", path, err)
	}
	if !strings.HasPrefix(rt.Schema, "stagecoach.runtime/") {
		return nil, fmt.Errorf("%s: not a stagecoach:inspect report (schema %q)", path, rt.Schema)
	}
	rt.index()
	return &rt, nil
}

func (rt *Runtime) index() {
	rt.enabled = map[string]bool{}
	for _, m := range rt.Modules.Enabled {
		rt.enabled[m.Name] = true
	}
}

func (rt *Runtime) moduleEnabled(name string) bool { return rt.enabled[name] }

// RuntimeFacts is the summary shown in reports.
type RuntimeFacts struct {
	Platform         string   `json:"platform"`
	Env              string   `json:"env,omitempty"`
	PHP              string   `json:"php"`
	Database         string   `json:"database"`
	DBSizeMB         float64  `json:"db_size_mb"`
	DBTransferMB     float64  `json:"db_transfer_mb"` // excluding cache tables
	FilesMB          float64  `json:"files_mb"`
	FilesCount       int      `json:"files_count"`
	EnabledModules   int      `json:"enabled_modules"`
	CustomEnabled    int      `json:"custom_modules_enabled"`
	CacheBackend     string   `json:"cache_backend"`
	SearchBackends   []string `json:"search_backends"`
	MailInterface    string   `json:"mail_interface"`
	DockerExtensions []string `json:"docker_php_extensions"`
	CollectorErrors  []string `json:"collector_errors,omitempty"`
}

// Extensions worth calling out when writing the Dockerfile. Core ones that
// every php image ships (ctype, json, pcre…) are left out on purpose.
var notableExtensions = map[string]bool{
	"apcu": true, "bcmath": true, "exif": true, "gd": true, "gmp": true, "igbinary": true, "imagick": true,
	"intl": true, "ldap": true, "memcache": true, "memcached": true, "mongodb": true, "opcache": true,
	"pdo_mysql": true, "pdo_pgsql": true, "pdo_sqlite": true, "redis": true, "soap": true, "sodium": true,
	"uploadprogress": true, "xsl": true, "zip": true, "newrelic": true, "blackfire": true,
}

func (rt *Runtime) facts() *RuntimeFacts {
	f := &RuntimeFacts{
		Platform:        rt.Environment.Platform,
		Env:             rt.Environment.Env,
		PHP:             rt.PHP.Version,
		Database:        strings.TrimSpace(rt.Database.Driver + " " + rt.Database.Version),
		EnabledModules:  rt.Modules.Count,
		CacheBackend:    rt.Cache.DefaultBackend,
		MailInterface:   rt.Mail.DefaultInterface,
		SearchBackends:  []string{},
		CollectorErrors: rt.Errors,
	}
	if rt.Database.SizeMB != nil {
		f.DBSizeMB = *rt.Database.SizeMB
		f.DBTransferMB = f.DBSizeMB
		if rt.Database.CacheTablesMB != nil {
			f.DBTransferMB = math.Round((f.DBSizeMB-*rt.Database.CacheTablesMB)*10) / 10
		}
	}
	for _, m := range rt.Files.Managed {
		f.FilesMB += m.SizeMB
		f.FilesCount += m.Count
	}
	f.FilesMB = math.Round(f.FilesMB*10) / 10
	for _, m := range rt.Modules.Enabled {
		if m.Type == "custom" {
			f.CustomEnabled++
		}
	}
	for _, s := range rt.Search.Servers {
		label := s.Backend
		if s.Connector != "" {
			label += " (" + s.Connector + ")"
		}
		f.SearchBackends = append(f.SearchBackends, label)
	}
	for _, e := range rt.PHP.Extensions {
		if notableExtensions[e] {
			f.DockerExtensions = append(f.DockerExtensions, e)
		}
	}
	sort.Strings(f.DockerExtensions)
	return f
}

// applyRuntime refines static findings with what's actually enabled, then adds
// runtime-only findings. It returns the new finding list.
func applyRuntime(rt *Runtime, findings []Finding) []Finding {
	out := findings[:0]
	mailOK := rt.Mail.DefaultInterface != "" && rt.Mail.DefaultInterface != "php_mail" ||
		rt.Mail.SymfonyMailer || rt.Mail.SymfonyMailerLite || rt.Mail.SMTP

	for _, f := range findings {
		if f.ID == "generic.no_mail_transport" {
			if mailOK {
				continue // a real transport is configured; the static guess was wrong
			}
			f.Severity = rules.Warning
			f.Evidence = append(f.Evidence, Evidence{Path: "runtime.json", Note: "system.mail uses php_mail"})
		}
		if f.composerOnly && len(f.modules) > 0 && !anyEnabled(rt, f.modules) {
			f.Title += " (installed, not enabled)"
			f.Severity = rules.Info
			f.EffortHours = 0.5
			f.Fix = "Not enabled on the running site, so just remove the package from composer.json."
			f.Evidence = append(f.Evidence, Evidence{Path: "runtime.json", Note: "module not enabled: " + strings.Join(f.modules, ", ")})
		}
		out = append(out, f)
	}

	add := func(id, title string, sev rules.Severity, hours float64, fix string, ev ...Evidence) {
		out = append(out, Finding{ID: id, Title: title, Platform: "generic", Category: "runtime",
			Severity: sev, EffortHours: hours, Fix: fix, Evidence: ev})
	}
	rtEv := func(note string) Evidence { return Evidence{Path: "runtime.json", Note: note} }

	if n := len(rt.Database.NonInnoDB); n > 0 {
		names := []string{}
		for i, t := range rt.Database.NonInnoDB {
			if i == 5 {
				names = append(names, "…")
				break
			}
			names = append(names, t.Name+" ("+t.Engine+")")
		}
		add("runtime.non_innodb", strconv.Itoa(n)+" non-InnoDB table(s)", rules.Warning, 2,
			"Convert to InnoDB (ALTER TABLE … ENGINE=InnoDB). Consistent single-transaction dumps for copy-downs require it.",
			rtEv(strings.Join(names, ", ")))
	}

	if rt.Database.SizeMB != nil {
		mb := *rt.Database.SizeMB
		if rt.Database.CacheTablesMB != nil {
			mb -= *rt.Database.CacheTablesMB
		}
		switch {
		case mb > 10240:
			add("runtime.large_database", "Large database", rules.Warning, 4,
				"Plan the cutover dump/restore window (or use replication/mydumper). Truncate cache tables first.",
				rtEv(fmt.Sprintf("%.1f GB excluding cache tables", mb/1024)))
		case mb > 2048:
			add("runtime.large_database", "Sizeable database", rules.Info, 1,
				"Time a test dump/restore before cutover. Truncate cache tables first.",
				rtEv(fmt.Sprintf("%.1f GB excluding cache tables", mb/1024)))
		}
	}

	var filesMB float64
	for _, m := range rt.Files.Managed {
		filesMB += m.SizeMB
	}
	switch {
	case filesMB > 51200:
		add("runtime.large_files", "Large file store", rules.Warning, 4,
			"Pre-seed files to S3 or the volume days ahead with incremental syncs (rclone / s5cmd), then do a final delta at cutover.",
			rtEv(fmt.Sprintf("%.1f GB managed files", filesMB/1024)))
	case filesMB > 5120:
		add("runtime.large_files", "Sizeable file store", rules.Info, 1,
			"Pre-seed files before cutover and sync the delta at cutover time.",
			rtEv(fmt.Sprintf("%.1f GB managed files", filesMB/1024)))
	}

	if rt.Cron.AutomatedCron {
		add("runtime.cron", "Cron runs on page requests (automated_cron)", rules.Info, 1,
			"Replace with a Kubernetes CronJob running drush cron, and uninstall automated_cron.", rtEv("automated_cron enabled"))
	} else {
		add("runtime.cron", "Platform-scheduled cron", rules.Info, 1,
			"The platform's cron scheduler doesn't come with you. Add a Kubernetes CronJob running drush cron.", rtEv("platform cron"))
	}

	for _, q := range rt.Queues {
		if q.Items > 1000 {
			add("runtime.queue_backlog", "Queue backlog: "+q.Name, rules.Info, 0.5,
				"Drain or deliberately carry over this queue before cutover.", rtEv(strconv.Itoa(q.Items)+" items"))
		}
	}

	if v := rt.PHP.Version; v != "" && versionLess(v, "8.2") {
		add("runtime.php_eol", "PHP "+v+" is end-of-life", rules.Warning, 4,
			"Build the image on PHP 8.3+ and run the test suite. Moving platforms is a good moment to take the upgrade.", rtEv("php "+v))
	}
	return out
}

func anyEnabled(rt *Runtime, modules []string) bool {
	for _, m := range modules {
		if rt.moduleEnabled(m) {
			return true
		}
	}
	return false
}

// versionLess compares dotted numeric versions (only major.minor matter here).
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 2; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
