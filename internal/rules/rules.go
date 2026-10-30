// Package rules loads the migration-readiness rule set.
//
// Rules are data, not code: the default set is embedded from default.json,
// and users can layer their own file on top with --rules (same id = override).
package rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

//go:embed default.json
var defaultRules []byte

type Severity string

const (
	Blocker Severity = "blocker"
	Warning Severity = "warning"
	Info    Severity = "info"
)

// Rank orders severities for sorting and --fail-on.
func (s Severity) Rank() int {
	switch s {
	case Blocker:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// ContentMatch greps files whose relative path matches Paths (and not Exclude).
type ContentMatch struct {
	Paths   []string `json:"paths"`
	Exclude []string `json:"exclude,omitempty"`
	Pattern string   `json:"pattern"`
}

// Match is OR-combined: a rule fires if any populated matcher hits.
type Match struct {
	Files        []string      `json:"files,omitempty"`         // path globs that exist in the repo
	Composer     []string      `json:"composer,omitempty"`      // any of these packages is required/locked
	ComposerNone []string      `json:"composer_none,omitempty"` // none of these packages is present
	Content      *ContentMatch `json:"content,omitempty"`
}

type Rule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Platform    string   `json:"platform"` // acquia | pantheon | generic
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	EffortHours float64  `json:"effort_hours"`
	Fix         string   `json:"fix"`
	Match       Match    `json:"match"`
	// SuppressedBy drops this finding when any listed rule also fired
	// (e.g. generic Solr is redundant next to Pantheon/Acquia Search).
	SuppressedBy []string `json:"suppressed_by,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
}

type file struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

func parse(b []byte, src string) ([]Rule, error) {
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", src, err)
	}
	for i, r := range f.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("%s: rule #%d has no id", src, i)
		}
		switch r.Severity {
		case Blocker, Warning, Info:
		default:
			return nil, fmt.Errorf("%s: rule %q has invalid severity %q", src, r.ID, r.Severity)
		}
	}
	return f.Rules, nil
}

// Load returns the embedded rules, overlaid with rules from extraPath (if set).
func Load(extraPath string) ([]Rule, error) {
	base, err := parse(defaultRules, "embedded default.json")
	if err != nil {
		return nil, err
	}
	byID := map[string]Rule{}
	order := []string{}
	for _, r := range base {
		byID[r.ID] = r
		order = append(order, r.ID)
	}
	if extraPath != "" {
		b, err := os.ReadFile(extraPath)
		if err != nil {
			return nil, err
		}
		extra, err := parse(b, extraPath)
		if err != nil {
			return nil, err
		}
		for _, r := range extra {
			if _, ok := byID[r.ID]; !ok {
				order = append(order, r.ID)
			}
			byID[r.ID] = r
		}
	}
	out := make([]Rule, 0, len(order))
	for _, id := range order {
		if r := byID[id]; !r.Disabled {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Platform < out[j].Platform })
	return out, nil
}
