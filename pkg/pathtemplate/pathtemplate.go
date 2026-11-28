// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pathtemplate matches HTTP request paths against google.api.http-style
// segment-scoped path templates and expands captures into structured redirect targets.
package pathtemplate

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

type segmentKind int

const (
	segmentMulti   segmentKind = 1
	rankExactEnd               = 2
	segmentSingle  segmentKind = 3
	segmentLiteral segmentKind = 4
)

type segment struct {
	kind  segmentKind
	value string
}

// Template is a compiled segment-scoped path template.
type Template struct {
	segments      []segment
	trailingSlash bool
	variables     map[string]struct{}
}

// Parse compiles a google.api.http-style path template such as "/{repo}/{path=**}".
func Parse(pattern string) (*Template, error) {
	if !strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "?#") {
		return nil, fmt.Errorf("invalid path template %q", pattern)
	}
	template := &Template{variables: map[string]struct{}{}}
	if pattern == "/" {
		return template, nil
	}
	trimmed, trailingSlash := strings.CutSuffix(pattern[1:], "/")
	template.trailingSlash = trailingSlash
	if trimmed == "" {
		return nil, fmt.Errorf("empty segment in %q", pattern)
	}
	rawSegments := strings.Split(trimmed, "/")
	for i, raw := range rawSegments {
		parsed, err := parseSegment(raw, template.variables)
		if err != nil {
			return nil, fmt.Errorf("path template %q: %w", pattern, err)
		}
		if parsed.kind == segmentMulti && (i != len(rawSegments)-1 || trailingSlash) {
			return nil, fmt.Errorf("path template %q: multi-segment wildcard must be terminal", pattern)
		}
		template.segments = append(template.segments, parsed)
	}
	return template, nil
}

func parseSegment(raw string, variables map[string]struct{}) (segment, error) {
	switch raw {
	case "":
		return segment{}, fmt.Errorf("empty segment")
	case "*":
		return segment{kind: segmentSingle}, nil
	case "**":
		return segment{kind: segmentMulti}, nil
	}
	if !strings.HasPrefix(raw, "{") || !strings.HasSuffix(raw, "}") {
		if strings.ContainsAny(raw, "{}*") {
			return segment{}, fmt.Errorf("invalid literal %q", raw)
		}
		return segment{kind: segmentLiteral, value: raw}, nil
	}
	name, expression, hasEquals := strings.Cut(raw[1:len(raw)-1], "=")
	if !validDotted(name, '_', false) {
		return segment{}, fmt.Errorf("invalid variable %q", raw)
	}
	if _, exists := variables[name]; exists {
		return segment{}, fmt.Errorf("duplicate variable %q", name)
	}
	kind := segmentSingle
	if hasEquals && expression == "**" {
		kind = segmentMulti
	} else if hasEquals && expression != "*" {
		return segment{}, fmt.Errorf("invalid wildcard %q", expression)
	}
	variables[name] = struct{}{}
	return segment{kind: kind, value: name}, nil
}

// Match matches requestPath against the template and returns captured variables.
//
// Invariant: multi-segment wildcards reject a leading empty segment so "//host"
// cannot match a root wildcard and produce a protocol-relative redirect.
func (t *Template) Match(requestPath string) (map[string]string, bool) {
	if !strings.HasPrefix(requestPath, "/") {
		return nil, false
	}
	captures := make(map[string]string, len(t.variables))
	remaining, hadSlash := requestPath[1:], false
	for _, current := range t.segments {
		if current.kind == segmentMulti {
			if strings.HasPrefix(remaining, "/") {
				return nil, false
			}
			if current.value != "" {
				captures[current.value] = remaining
			}
			return captures, true
		}
		part, after, found := strings.Cut(remaining, "/")
		if part == "" || (current.kind == segmentLiteral && part != current.value) {
			return nil, false
		}
		if current.kind == segmentSingle && current.value != "" {
			captures[current.value] = part
		}
		remaining, hadSlash = after, found
	}
	if remaining != "" || hadSlash != t.trailingSlash {
		return nil, false
	}
	return captures, true
}

// CompareSpecificity reports whether t is more specific than other (-1), equal (0),
// or less specific (+1). Literals beat single wildcards, exact ends beat trailing
// multi-segment wildcards, and single wildcards beat multi-segment wildcards.
func (t *Template) CompareSpecificity(other *Template) int {
	for i := 0; i < max(len(t.segments), len(other.segments)); i++ {
		left, right := rankExactEnd, rankExactEnd
		if i < len(t.segments) {
			left = int(t.segments[i].kind)
		}
		if i < len(other.segments) {
			right = int(other.segments[i].kind)
		}
		if order := cmp.Compare(right, left); order != 0 {
			return order
		}
	}
	return 0
}

// QueryMode controls how a redirect handles incoming query parameters.
type QueryMode string

const (
	QueryPreserve QueryMode = "preserve"
	QueryAppend   QueryMode = "append"
	QueryReplace  QueryMode = "replace"
	QueryDrop     QueryMode = "drop"
)

// Target describes a structured redirect destination.
//
// Invariant: NewMatcher validates Scheme and Hostname as static values and never
// expands captures into them, preventing open redirects.
type Target struct {
	Scheme    string
	Hostname  string
	Path      string
	Query     string
	Fragment  string
	QueryMode QueryMode
}

// Rule pairs a path template pattern with a redirect target.
type Rule struct {
	Pattern string
	Target  Target
}

type targetPart struct {
	literal  string
	variable string
}

type compiledRule struct {
	template *Template
	target   Target
	parts    [3][]targetPart // path, query, fragment
}

// Matcher evaluates compiled redirect rules in specificity order, breaking ties
// by declaration order.
type Matcher struct {
	rules []compiledRule
}

// NewMatcher compiles rules and orders them by descending specificity.
func NewMatcher(rules ...Rule) (*Matcher, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		entry, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		compiled = append(compiled, entry)
	}
	slices.SortStableFunc(compiled, func(left, right compiledRule) int {
		return left.template.CompareSpecificity(right.template)
	})
	return &Matcher{rules: compiled}, nil
}

func compileRule(rule Rule) (compiledRule, error) {
	template, err := Parse(rule.Pattern)
	if err != nil {
		return compiledRule{}, err
	}
	target := rule.Target
	if (target.Scheme == "") != (target.Hostname == "") ||
		(target.Scheme != "" && target.Scheme != "http" && target.Scheme != "https") ||
		(target.Hostname != "" && !validDotted(target.Hostname, '-', true)) {
		return compiledRule{}, fmt.Errorf("invalid target scheme %q or hostname %q", target.Scheme, target.Hostname)
	}
	if target.Path != "" && (target.Path[0] != '/' || strings.HasPrefix(target.Path, "//") || strings.ContainsAny(target.Path, "?#")) {
		return compiledRule{}, fmt.Errorf("invalid target path %q", target.Path)
	}
	if strings.HasPrefix(target.Query, "?") || strings.Contains(target.Query, "#") || strings.Contains(target.Fragment, "#") {
		return compiledRule{}, fmt.Errorf("invalid target query %q or fragment %q", target.Query, target.Fragment)
	}
	switch target.QueryMode {
	case "":
		target.QueryMode = QueryPreserve
		if target.Query != "" {
			target.QueryMode = QueryReplace
		}
	case QueryPreserve, QueryAppend, QueryReplace, QueryDrop:
	default:
		return compiledRule{}, fmt.Errorf("invalid query mode %q", target.QueryMode)
	}
	var parsed [3][]targetPart
	for i, raw := range [3]string{target.Path, target.Query, target.Fragment} {
		parts, err := parseTarget(raw, template.variables)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid target %q: %w", raw, err)
		}
		parsed[i] = parts
	}
	return compiledRule{template: template, target: target, parts: parsed}, nil
}

// Match returns the expanded redirect URL from the most specific matching rule.
// Match escapes captures with path escaping in path and fragment components and
// with query escaping in query components, while preserving literal percent-encoding
// in target templates and emitting query parameters before any fragment.
func (m *Matcher) Match(requestPath, incomingQuery string) (string, bool) {
	for _, rule := range m.rules {
		captures, ok := rule.template.Match(requestPath)
		if !ok {
			continue
		}
		var builder strings.Builder
		if rule.target.Scheme != "" {
			builder.WriteString(rule.target.Scheme + "://" + rule.target.Hostname)
		}
		builder.WriteString(expandParts(rule.parts[0], captures, escapePath))
		if query := combineQuery(rule.target.QueryMode, expandParts(rule.parts[1], captures, url.QueryEscape), incomingQuery); query != "" {
			builder.WriteByte('?')
			builder.WriteString(query)
		}
		if fragment := expandParts(rule.parts[2], captures, escapePath); fragment != "" {
			builder.WriteByte('#')
			builder.WriteString(fragment)
		}
		return builder.String(), true
	}
	return "", false
}

func parseTarget(raw string, variables map[string]struct{}) ([]targetPart, error) {
	var parts []targetPart
	for raw != "" {
		open, close := strings.IndexByte(raw, '{'), strings.IndexByte(raw, '}')
		if open == -1 && close == -1 {
			return append(parts, targetPart{literal: raw}), nil
		}
		if open == -1 || close < open {
			return nil, fmt.Errorf("malformed braces")
		}
		name := raw[open+1 : close]
		if _, ok := variables[name]; !ok {
			return nil, fmt.Errorf("unknown variable %q", name)
		}
		parts = append(parts, targetPart{literal: raw[:open], variable: name})
		raw = raw[close+1:]
	}
	return parts, nil
}

func expandParts(parts []targetPart, captures map[string]string, escape func(string) string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(part.literal)
		if part.variable != "" {
			builder.WriteString(escape(captures[part.variable]))
		}
	}
	return builder.String()
}

func combineQuery(mode QueryMode, targetQuery, incomingQuery string) string {
	incomingQuery = strings.TrimPrefix(incomingQuery, "?")
	switch mode {
	case QueryPreserve:
		if incomingQuery != "" {
			return incomingQuery
		}
		return targetQuery
	case QueryAppend:
		if targetQuery != "" && incomingQuery != "" {
			return targetQuery + "&" + incomingQuery
		}
		return targetQuery + incomingQuery
	case QueryReplace:
		return targetQuery
	default:
		return ""
	}
}

func escapePath(value string) string {
	parts := strings.Split(value, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func validDotted(value string, extra byte, hostname bool) bool {
	for _, label := range strings.Split(value, ".") {
		if label == "" || (!hostname && label[0] >= '0' && label[0] <= '9') || (hostname && (label[0] == '-' || label[len(label)-1] == '-')) {
			return false
		}
		for i := 0; i < len(label); i++ {
			character := label[i]
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == extra) {
				return false
			}
		}
	}
	return true
}
