package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jtarleton/stagecoach-scan/internal/rules"
)

func TestRuntimeMerge(t *testing.T) {
	rt, err := LoadRuntime(filepath.Join("testdata", "acquia-runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := run(t, "acquia-site", Options{Runtime: rt})
	got := ids(res)

	// Installed via composer but not enabled -> downgraded to info.
	if f := got["acquia.search"]; f.Severity != rules.Info || f.EffortHours != 0.5 {
		t.Errorf("acquia.search should be downgraded, got %+v", f)
	}
	// Enabled modules keep their severity.
	if f := got["acquia.purge"]; f.Severity != rules.Warning {
		t.Errorf("acquia.purge should stay a warning, got %s", f.Severity)
	}
	for _, want := range []string{"runtime.non_innodb", "runtime.large_database", "runtime.large_files",
		"runtime.cron", "runtime.queue_backlog", "runtime.php_eol"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing runtime finding %s", want)
		}
	}
	if got["runtime.large_database"].Severity != rules.Warning {
		t.Error("12 GB excluding cache tables should be a warning")
	}
	rf := res.Facts.Runtime
	if rf == nil || rf.Env != "prod" || rf.DBTransferMB != 12288 || rf.CustomEnabled != 1 {
		t.Fatalf("runtime facts = %+v", rf)
	}
	if res.Facts.Platform != "acquia" {
		t.Errorf("platform = %s", res.Facts.Platform)
	}
}

func TestRuntimeMailOverridesStaticGuess(t *testing.T) {
	// Pantheon fixture has no mail module in composer -> static info finding.
	rt := &Runtime{Schema: "stagecoach.runtime/v1"}
	rt.Mail.DefaultInterface = "php_mail"
	if f := ids(run(t, "pantheon-site", Options{Runtime: rt}))["generic.no_mail_transport"]; f.Severity != rules.Warning {
		t.Errorf("php_mail at runtime should escalate to warning, got %q", f.Severity)
	}
	rt.Mail.DefaultInterface = "symfony_mailer"
	if _, ok := ids(run(t, "pantheon-site", Options{Runtime: rt}))["generic.no_mail_transport"]; ok {
		t.Error("a configured transport should drop the static mail finding")
	}
}

func TestLoadRuntimeRejectsOtherJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(p, []byte(`{"tool":"stagecoach-scan"}`), 0o600)
	if _, err := LoadRuntime(p); err == nil {
		t.Error("expected schema error")
	}
}

func TestVersionLess(t *testing.T) {
	if !versionLess("8.1.27", "8.2") || versionLess("8.3.1", "8.2") || versionLess("8.2.0", "8.2") {
		t.Error("versionLess broken")
	}
}
