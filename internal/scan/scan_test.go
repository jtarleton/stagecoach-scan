package scan

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jtarleton/stagecoach-scan/internal/rules"
)

func run(t *testing.T, fixture string, opt Options) *Result {
	t.Helper()
	rs, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(filepath.Join("testdata", fixture), rs, opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(res *Result) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range res.Findings {
		m[f.ID] = f
	}
	return m
}

func TestPantheonFixture(t *testing.T) {
	res := run(t, "pantheon-site", Options{ShowSnippets: true})
	got := ids(res)

	for _, want := range []string{
		"pantheon.yml", "pantheon.quicksilver", "pantheon.settings_include", "pantheon.env_vars",
		"pantheon.search", "pantheon.advanced_page_cache", "pantheon.terminus_ci",
		"pantheon.drupal_integrations", "generic.redis", "generic.no_mail_transport",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing finding %s", want)
		}
	}
	for _, unwanted := range []string{"generic.solr", "core.no_config_sync", "core.unsupported", "acquia.site_php"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("unexpected finding %s", unwanted)
		}
	}
	if res.Facts.Platform != "pantheon" || res.Facts.DrupalCore != "10.3.6" || res.Facts.Docroot != "web" {
		t.Errorf("facts = %+v", res.Facts)
	}
	if res.Facts.PantheonPHP != "8.2" || res.Facts.ConfigSyncDir != "config/sync" {
		t.Errorf("facts = %+v", res.Facts)
	}
	// settings.pantheon.php is scaffolded by Pantheon and must not count as custom code.
	for _, e := range got["pantheon.env_vars"].Evidence {
		if strings.HasSuffix(e.Path, "settings.pantheon.php") {
			t.Errorf("settings.pantheon.php should be excluded: %v", e)
		}
	}
}

func TestAcquiaFixture(t *testing.T) {
	res := run(t, "acquia-site", Options{})
	got := ids(res)
	for _, want := range []string{
		"acquia.site_php", "acquia.env_vars", "acquia.cloud_hooks", "acquia.pipelines", "acquia.blt",
		"acquia.purge", "acquia.search", "acquia.connector", "acquia.gfs_paths",
		"generic.memcache", "generic.saml", "generic.private_files",
		"core.unsupported", "core.multisite", "core.no_config_sync", "core.committed_uploads",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing finding %s", want)
		}
	}
	if _, ok := got["generic.no_mail_transport"]; ok {
		t.Error("symfony_mailer is present; no_mail_transport should not fire")
	}
	if res.Facts.Platform != "acquia" || res.Facts.DrupalMajor != 9 || len(res.Facts.Sites) != 2 {
		t.Errorf("facts = %+v", res.Facts)
	}
	if res.Summary.Blockers < 3 || res.Summary.Readiness == "Ready" {
		t.Errorf("summary = %+v", res.Summary)
	}
	if res.Findings[0].Severity != rules.Blocker {
		t.Error("findings should be sorted blockers first")
	}
	// Without --show-snippets, evidence carries locations only.
	for _, f := range res.Findings {
		for _, e := range f.Evidence {
			if e.Snippet != "" {
				t.Fatalf("snippet leaked without --show-snippets: %+v", e)
			}
		}
	}
}

// The report must never contain secrets, .env contents or absolute paths.
func TestNoLeaks(t *testing.T) {
	res := run(t, "pantheon-site", Options{ShowSnippets: true})
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	abs, _ := filepath.Abs("testdata")
	for _, bad := range []string{"hunter2", "supersecret", "DB_PASSWORD", `"path": ".env"`, abs} {
		if strings.Contains(out, bad) {
			t.Errorf("report leaks %q", bad)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		`$databases['default']['default']['password'] = 'hunter2';`: `$databases['***']['***']['***'] = '***';`,
		`if ($_ENV['AH_SITE_ENVIRONMENT'] === "prod") {`:            `if ($_ENV['AH_SITE_ENVIRONMENT'] === "prod") {`,
		`require "/var/www/site-php/x/x-settings.inc";`:             `require "***";`,
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"**/sites/*/settings.php", "web/sites/default/settings.php", true},
		{"**/sites/*/settings.php", "sites/default/settings.php", true},
		{"**/sites/*/settings.php", "web/sites/default/files/settings.php", false},
		{"**/*.module", "web/modules/custom/x/x.module", true},
		{".github/workflows/*.yml", ".github/workflows/deploy.yml", true},
		{"hooks/*/post-code-deploy", "hooks/common/post-code-deploy", true},
		{"pantheon.yml", "sub/pantheon.yml", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.path); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
}
