# stagecoach-scan

An offline scanner that checks a Drupal repository for **Acquia / Pantheon lock-in** and estimates the work needed to move it to self-hosted Kubernetes with [Stagecoach](https://stagecoach.sh).

- **Runs on your machine.** No network calls, no credentials, no telemetry.
- **Never reads secrets.** `.env*`, keys, certificates and SQL dumps are skipped. Reports contain file paths and line numbers only; `--show-snippets` adds matched lines with every string literal masked.
- **Zero dependencies.** Go standard library only, so it's quick to audit.

## Install

Download a binary from [Releases](https://github.com/jtarleton/stagecoach-scan/releases) and verify it was built by this repo's release workflow:

```sh
gh attestation verify stagecoach-scan-darwin-arm64 --repo jtarleton/stagecoach-scan
sha256sum -c checksums.txt --ignore-missing
```

Or build it yourself:

```sh
go install github.com/jtarleton/stagecoach-scan@latest
# or build from source
make build   # -> bin/stagecoach-scan
```

## Usage

```sh
cd my-drupal-site
stagecoach-scan scan                                # coloured text report
stagecoach-scan scan . --format html --out report.html
stagecoach-scan scan . --format json --out report.json
stagecoach-scan scan . --fail-on blocker            # exit 2 in CI if blockers exist
stagecoach-scan rules                               # list active rules
```

## Add runtime facts (optional)

Static analysis can't see database size, enabled modules or which backends are actually configured. The companion Drupal module Stagecoach Inspect, a submodule of [`stage_coach`](https://www.drupal.org/project/stage_coach) that works without a Stagecoach server, prints those as redacted JSON:

```sh
composer require 'drupal/stage_coach:^1.0@alpha' && drush en stagecoach_inspect -y
drush stagecoach:inspect > runtime.json          # or: terminus drush site.live -- stagecoach:inspect
stagecoach-scan scan . --runtime runtime.json --format html --out report.html
```

With runtime data the scanner:
- downgrades findings for packages that are installed but **not enabled** (e.g. a leftover `acquia_search`)
- drops or escalates the mail-transport guess based on the real `system.mail` setting
- adds runtime checks: non-InnoDB tables, large database (excluding cache tables), large file store, cron replacement, queue backlogs, PHP end of life
- lists the PHP extensions your Docker image needs

## What it checks

| Area | Examples |
|---|---|
| Pantheon | `pantheon.yml`, Quicksilver hooks, `settings.pantheon.php`, `PANTHEON_ENVIRONMENT`, Pantheon Search, Advanced Page Cache, Terminus in CI |
| Acquia | `/var/www/site-php` includes, `AH_SITE_ENVIRONMENT`, Cloud Hooks, Pipelines, BLT, Acquia Purge / Search / Connector, Site Factory, `/mnt/gfs` paths |
| Services | Memcache, Redis, Solr, SimpleSAMLphp, mail transport, private files, S3 |
| Core | Drupal version (7 / pre-10 flagged), missing `composer.lock`, no config export, multisite, uploads committed to git |

Each finding includes a severity (blocker / warning / info), a fix, and a rough effort estimate. The score starts at 100 and loses 15 points per blocker and 5 per warning. The effort range adds an 8-hour baseline (Dockerfile, settings, provisioning, cutover) and is shown as 0.75×–1.5×.

## Custom rules

Rules are data in [`internal/rules/default.json`](internal/rules/default.json). Add your own, or override or disable built-ins by `id`:

```sh
stagecoach-scan scan . --rules my-rules.json
```

```json
{
  "version": 1,
  "rules": [
    {
      "id": "agency.legacy_cdn",
      "title": "Legacy CDN module",
      "platform": "generic", "category": "cdn", "severity": "warning", "effort_hours": 3,
      "fix": "Replace with the Purge + Cloudflare purger.",
      "match": { "composer": ["drupal/old_cdn"] }
    },
    { "id": "generic.no_mail_transport", "title": "", "platform": "generic", "category": "", "severity": "info", "fix": "", "match": {}, "disabled": true }
  ]
}
```

Matchers (OR-combined): `files` (path globs, `**` supported), `composer` (any package present), `composer_none` (none present), `content` (`paths` + `exclude` globs + RE2 `pattern`, line by line). `suppressed_by` hides a finding when a more specific rule fires.

## Layout

```
main.go                     CLI (scan, rules, version)
internal/rules/             rule schema + embedded default.json
internal/scan/              walker, matchers, built-in core checks, scoring, redaction
internal/scan/runtime.go    --runtime merge and runtime-only checks
internal/scan/testdata/     Pantheon and Acquia fixture repos + a runtime.json
.github/workflows/          CI (fmt, vet, test, cross-compile) and signed tag releases
internal/report/            text, JSON and self-contained HTML output
```

## Licence

MIT. See [LICENSE](LICENSE).
