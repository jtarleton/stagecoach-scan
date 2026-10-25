package scan

import (
	"regexp"
	"strings"
	"sync"
)

var globCache sync.Map

// globMatch matches a slash-separated relative path against a glob.
// Supports "**" (any number of path segments), "*" (within a segment) and "?".
func globMatch(pattern, path string) bool {
	re, ok := globCache.Load(pattern)
	if !ok {
		re = compileGlob(pattern)
		globCache.Store(pattern, re)
	}
	return re.(*regexp.Regexp).MatchString(path)
}

func compileGlob(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString("(?:.*/)?") // "**/" = zero or more directories
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func anyGlob(patterns []string, path string) bool {
	for _, p := range patterns {
		if globMatch(p, path) {
			return true
		}
	}
	return false
}
