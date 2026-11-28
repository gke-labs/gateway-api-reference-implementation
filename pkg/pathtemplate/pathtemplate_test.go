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

package pathtemplate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/pathtemplate"
)

func TestGitK8sIO(t *testing.T) {
	// Declare the multi-segment rule before the single-segment rules to confirm
	// that specificity ordering overrides declaration order.
	matcher, err := pathtemplate.NewMatcher(
		pathtemplate.Rule{
			Pattern: "/{repo}/{path=**}",
			Target: pathtemplate.Target{
				Scheme:   "https",
				Hostname: "github.com",
				Path:     "/kubernetes/{repo}/blob/master/{path}",
			},
		},
		pathtemplate.Rule{
			Pattern: "/{repo}",
			Target: pathtemplate.Target{
				Scheme:   "https",
				Hostname: "github.com",
				Path:     "/kubernetes/{repo}",
			},
		},
		pathtemplate.Rule{
			Pattern: "/{repo}/",
			Target: pathtemplate.Target{
				Scheme:   "https",
				Hostname: "github.com",
				Path:     "/kubernetes/{repo}",
			},
		},
	)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	cases := []struct {
		name  string
		path  string
		query string
		want  string
		ok    bool
	}{
		{
			name: "single segment repo",
			path: "/kubernetes",
			want: "https://github.com/kubernetes/kubernetes",
			ok:   true,
		},
		{
			name: "single segment repo with trailing slash",
			path: "/kubernetes/",
			want: "https://github.com/kubernetes/kubernetes",
			ok:   true,
		},
		{
			name: "single segment file under repo",
			path: "/kubernetes/README.md",
			want: "https://github.com/kubernetes/kubernetes/blob/master/README.md",
			ok:   true,
		},
		{
			name: "nested path under repo",
			path: "/kubernetes/pkg/api/v1",
			want: "https://github.com/kubernetes/kubernetes/blob/master/pkg/api/v1",
			ok:   true,
		},
		{
			name: "nested path preserves trailing slash",
			path: "/kubernetes/pkg/api/",
			want: "https://github.com/kubernetes/kubernetes/blob/master/pkg/api/",
			ok:   true,
		},
		{
			name: "root path does not match",
			path: "/",
			ok:   false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := matcher.Match(testCase.path, testCase.query)
			if ok != testCase.ok || got != testCase.want {
				t.Errorf("Match(%q, %q) = (%q, %v), want (%q, %v)", testCase.path, testCase.query, got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

func TestTrailingSlashSensitivity(t *testing.T) {
	// Matches ci-test.k8s.io/e2e/ vs ci-test.k8s.io/e2e/file from #1601.
	matcher, err := pathtemplate.NewMatcher(
		pathtemplate.Rule{
			Pattern: "/e2e/{file=**}",
			Target: pathtemplate.Target{
				Scheme:   "https",
				Hostname: "storage.googleapis.com",
				Path:     "/kubernetes-ci-logs/e2e/{file}",
			},
		},
		pathtemplate.Rule{
			Pattern: "/e2e/",
			Target: pathtemplate.Target{
				Scheme:   "https",
				Hostname: "gcsweb.k8s.io",
				Path:     "/gcs/kubernetes-ci-logs/e2e/",
			},
		},
	)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	got, ok := matcher.Match("/e2e/", "")
	if !ok || got != "https://gcsweb.k8s.io/gcs/kubernetes-ci-logs/e2e/" {
		t.Errorf("Match(/e2e/) = (%q, %v), want gcsweb directory redirect", got, ok)
	}

	got, ok = matcher.Match("/e2e/build-log.txt", "")
	if !ok || got != "https://storage.googleapis.com/kubernetes-ci-logs/e2e/build-log.txt" {
		t.Errorf("Match(/e2e/build-log.txt) = (%q, %v), want file redirect", got, ok)
	}

	// Without a /e2e rule, /e2e matches /e2e/{file=**} with zero trailing segments.
	got, ok = matcher.Match("/e2e", "")
	if !ok || got != "https://storage.googleapis.com/kubernetes-ci-logs/e2e/" {
		t.Errorf("Match(/e2e) = (%q, %v), want zero-segment wildcard match", got, ok)
	}
}

func TestGoK8sIOOwners(t *testing.T) {
	matcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/owners/{user}",
		Target: pathtemplate.Target{
			Scheme:    "https",
			Hostname:  "cs.k8s.io",
			Path:      "/",
			Query:     "q={user}&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=",
			QueryMode: pathtemplate.QueryReplace,
		},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	cases := []struct {
		name  string
		path  string
		query string
		want  string
		ok    bool
	}{
		{
			name: "normal user preserves literal percent encoding",
			path: "/owners/thockin",
			want: "https://cs.k8s.io/?q=thockin&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=",
			ok:   true,
		},
		{
			name: "user with query delimiters is escaped against parameter injection",
			path: "/owners/alice&repos=secret#frag",
			want: "https://cs.k8s.io/?q=alice%26repos%3Dsecret%23frag&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=",
			ok:   true,
		},
		{
			name:  "incoming query is replaced",
			path:  "/owners/thockin",
			query: "extra=1",
			want:  "https://cs.k8s.io/?q=thockin&i=fosho&files=OWNERS&excludeFiles=vendor%2F&repos=",
			ok:    true,
		},
		{
			name: "empty user segment does not match",
			path: "/owners/",
			ok:   false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := matcher.Match(testCase.path, testCase.query)
			if ok != testCase.ok || got != testCase.want {
				t.Errorf("Match(%q, %q) = (%q, %v), want (%q, %v)", testCase.path, testCase.query, got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

func TestRelK8sIORetro(t *testing.T) {
	matcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{ver}/retro",
		Target: pathtemplate.Target{
			Scheme:   "https",
			Hostname: "github.com",
			Path:     "/kubernetes/sig-release/tree/master/releases/release-{ver}/links.md",
			Fragment: "retro",
		},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	cases := []struct {
		name  string
		path  string
		query string
		want  string
	}{
		{
			name: "bare version segment",
			path: "/1.32/retro",
			want: "https://github.com/kubernetes/sig-release/tree/master/releases/release-1.32/links.md#retro",
		},
		{
			// Segment-scoped {ver} captures the full segment rather than stripping a
			// leading "v" prefix as regex ^/v?([0-9]+\.[0-9]+)/retro$ would.
			name: "leading v is captured verbatim by segment-scoped variable",
			path: "/v1.32/retro",
			want: "https://github.com/kubernetes/sig-release/tree/master/releases/release-v1.32/links.md#retro",
		},
		{
			name:  "incoming query appears before fragment",
			path:  "/1.32/retro",
			query: "plain=1",
			want:  "https://github.com/kubernetes/sig-release/tree/master/releases/release-1.32/links.md?plain=1#retro",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := matcher.Match(testCase.path, testCase.query)
			if !ok || got != testCase.want {
				t.Errorf("Match(%q, %q) = (%q, %v), want (%q, true)", testCase.path, testCase.query, got, ok, testCase.want)
			}
		})
	}
}

func TestSBOMK8sIO(t *testing.T) {
	matcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{ver=*}/release.sig",
		Target: pathtemplate.Target{
			Scheme:   "https",
			Hostname: "dl.k8s.io",
			Path:     "/release/{ver}/kubernetes-release.spdx.sig",
		},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	got, ok := matcher.Match("/v1.32.0/release.sig", "")
	want := "https://dl.k8s.io/release/v1.32.0/kubernetes-release.spdx.sig"
	if !ok || got != want {
		t.Errorf("Match = (%q, %v), want (%q, true)", got, ok, want)
	}

	if _, ok := matcher.Match("/v1.32.0/extra/release.sig", ""); ok {
		t.Errorf("expected multi-segment version not to match single-segment {ver=*}")
	}
}

func TestSpecificityAndTieBreaking(t *testing.T) {
	matcher, err := pathtemplate.NewMatcher(
		pathtemplate.Rule{
			Pattern: "/{rest=**}",
			Target:  pathtemplate.Target{Path: "/multi/{rest}"},
		},
		pathtemplate.Rule{
			Pattern: "/{first}/{second}",
			Target:  pathtemplate.Target{Path: "/first-two/{first}/{second}"},
		},
		pathtemplate.Rule{
			Pattern: "/{alpha}/{beta}",
			Target:  pathtemplate.Target{Path: "/second-two/{alpha}/{beta}"},
		},
		pathtemplate.Rule{
			Pattern: "/items/{id}",
			Target:  pathtemplate.Target{Path: "/literal-single/{id}"},
		},
		pathtemplate.Rule{
			Pattern: "/items/special",
			Target:  pathtemplate.Target{Path: "/literal-literal"},
		},
		pathtemplate.Rule{
			Pattern: "/",
			Target:  pathtemplate.Target{Path: "/root"},
		},
	)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	cases := []struct {
		path string
		want string
	}{
		{"/", "/root"},
		{"/items/special", "/literal-literal"},
		{"/items/42", "/literal-single/42"},
		{"/foo/bar", "/first-two/foo/bar"},
		{"/foo/bar/baz", "/multi/foo/bar/baz"},
	}
	for _, testCase := range cases {
		got, ok := matcher.Match(testCase.path, "")
		if !ok || got != testCase.want {
			t.Errorf("Match(%q) = (%q, %v), want (%q, true)", testCase.path, got, ok, testCase.want)
		}
	}
}

func TestQueryModes(t *testing.T) {
	cases := []struct {
		name     string
		target   pathtemplate.Target
		incoming string
		want     string
	}{
		{
			name: "preserve keeps incoming query when no target query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Fragment: "top",
				QueryMode: pathtemplate.QueryPreserve,
			},
			incoming: "a=1&b=2",
			want:     "https://example.com/42?a=1&b=2#top",
		},
		{
			name: "preserve falls back to target query when incoming is empty",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "default=1", Fragment: "top",
				QueryMode: pathtemplate.QueryPreserve,
			},
			incoming: "",
			want:     "https://example.com/42?default=1#top",
		},
		{
			name: "preserve keeps incoming over target query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "default=1", Fragment: "top",
				QueryMode: pathtemplate.QueryPreserve,
			},
			incoming: "a=1",
			want:     "https://example.com/42?a=1#top",
		},
		{
			name: "append combines target and incoming queries before fragment",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "id={id}", Fragment: "sec",
				QueryMode: pathtemplate.QueryAppend,
			},
			incoming: "extra=1",
			want:     "https://example.com/42?id=42&extra=1#sec",
		},
		{
			name: "append with empty incoming emits target query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "id={id}",
				QueryMode: pathtemplate.QueryAppend,
			},
			incoming: "",
			want:     "https://example.com/42?id=42",
		},
		{
			name: "append with empty target emits incoming query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}",
				QueryMode: pathtemplate.QueryAppend,
			},
			incoming: "extra=1",
			want:     "https://example.com/42?extra=1",
		},
		{
			name: "replace discards incoming query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "id={id}", Fragment: "sec",
				QueryMode: pathtemplate.QueryReplace,
			},
			incoming: "extra=1",
			want:     "https://example.com/42?id=42#sec",
		},
		{
			name: "replace with empty target drops incoming query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}",
				QueryMode: pathtemplate.QueryReplace,
			},
			incoming: "extra=1",
			want:     "https://example.com/42",
		},
		{
			name: "drop removes both incoming and target query",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "id={id}", Fragment: "sec",
				QueryMode: pathtemplate.QueryDrop,
			},
			incoming: "extra=1",
			want:     "https://example.com/42#sec",
		},
		{
			name: "default mode preserves incoming when target query is empty",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Fragment: "sec",
			},
			incoming: "extra=1",
			want:     "https://example.com/42?extra=1#sec",
		},
		{
			name: "default mode replaces incoming when target query is set",
			target: pathtemplate.Target{
				Scheme: "https", Hostname: "example.com", Path: "/{id}", Query: "id={id}", Fragment: "sec",
			},
			incoming: "extra=1",
			want:     "https://example.com/42?id=42#sec",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			matcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
				Pattern: "/{id}",
				Target:  testCase.target,
			})
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}
			got, ok := matcher.Match("/42", testCase.incoming)
			if !ok || got != testCase.want {
				t.Errorf("Match(/42, %q) = (%q, %v), want (%q, true)", testCase.incoming, got, ok, testCase.want)
			}
		})
	}
}

func TestCaptureEscapingAndSafety(t *testing.T) {
	matcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{name}/{rest=**}",
		Target: pathtemplate.Target{
			Scheme:   "https",
			Hostname: "example.com",
			Path:     "/p/{name}/{rest}",
			Query:    "literal=a%2Fb&n={name}",
			Fragment: "f-{name}",
		},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	got, ok := matcher.Match("/a#b?c d/dir/my file#1?x=2", "")
	want := "https://example.com/p/a%23b%3Fc%20d/dir/my%20file%231%3Fx=2?literal=a%2Fb&n=a%23b%3Fc+d#f-a%23b%3Fc%20d"
	if !ok || got != want {
		t.Errorf("Match = (%q, %v), want (%q, true)", got, ok, want)
	}

	// Root multi-segment wildcard must not match protocol-relative "//evil.com".
	rootMatcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{path=**}",
		Target:  pathtemplate.Target{Path: "/{path}"},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}
	if location, ok := rootMatcher.Match("//evil.com", ""); ok {
		t.Errorf("expected //evil.com not to match, got %q", location)
	}
}

func TestTemplateMatchDirectly(t *testing.T) {
	template, err := pathtemplate.Parse("/v1/*/users/{user.id}/{rest=**}")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	captures, ok := template.Match("/v1/org1/users/u42/a/b")
	if !ok {
		t.Fatalf("expected match")
	}
	want := map[string]string{
		"user.id": "u42",
		"rest":    "a/b",
	}
	if diff := cmp.Diff(want, captures); diff != "" {
		t.Errorf("captures mismatch (-want +got):\n%s", diff)
	}
	if _, ok := template.Match(""); ok {
		t.Errorf("expected empty path not to match")
	}
	if _, ok := template.Match("v1/org1/users/u42"); ok {
		t.Errorf("expected path without leading slash not to match")
	}
}

func TestCompareSpecificity(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  int
	}{
		{"/a/b", "/a/{x}", -1},
		{"/a/{x}", "/a/{x=**}", -1},
		{"/{repo}", "/{repo}/{path=**}", -1},
		{"/", "/{path=**}", -1},
		{"/a/{x}", "/{x}/a", -1},
		{"/{a}", "/{b}", 0},
		{"/{a=*}", "/{b}", 0},
		{"/{a=**}", "/{b=**}", 0},
		{"/a/{x=**}", "/a/{x}", 1},
	}

	for _, testCase := range cases {
		left, err := pathtemplate.Parse(testCase.left)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", testCase.left, err)
		}
		right, err := pathtemplate.Parse(testCase.right)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", testCase.right, err)
		}
		if got := left.CompareSpecificity(right); got != testCase.want {
			t.Errorf("CompareSpecificity(%q, %q) = %d, want %d", testCase.left, testCase.right, got, testCase.want)
		}
	}
}

func TestInvalidTemplates(t *testing.T) {
	invalidPatterns := []string{
		"",
		"no-leading-slash",
		"//",
		"/a//b",
		"/a?b=c",
		"/a#frag",
		"/{}",
		"/{=*}",
		"/{a=}",
		"/{a=foo}",
		"/{a=**/*}",
		"/{1bad}",
		"/{bad-name}",
		"/{a..b}",
		"/{.a}",
		"/{a.}",
		"/{unclosed",
		"/stray}",
		"/pre{a}",
		"/{a}suf",
		"/{a}{b}",
		"/foo*",
		"/***",
		"/{a}/{a}",
		"/{a}/{a=**}",
		"/{a=**}/tail",
		"/{a=**}/{b}",
		"/{a=**}/",
		"/**/tail",
		"/**/",
	}

	for _, pattern := range invalidPatterns {
		t.Run(pattern, func(t *testing.T) {
			if _, err := pathtemplate.Parse(pattern); err == nil {
				t.Errorf("Parse(%q) succeeded, want error", pattern)
			}
		})
	}
}

func TestInvalidTargets(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		target  pathtemplate.Target
	}{
		{
			name:   "empty target",
			target: pathtemplate.Target{},
		},
		{
			name:   "relative target with only query",
			target: pathtemplate.Target{Query: "q={a}"},
		},
		{
			name:   "relative target with only fragment",
			target: pathtemplate.Target{Fragment: "{a}"},
		},
		{
			name:   "scheme without hostname",
			target: pathtemplate.Target{Scheme: "https", Path: "/{a}"},
		},
		{
			name:   "hostname without scheme",
			target: pathtemplate.Target{Hostname: "example.com", Path: "/{a}"},
		},
		{
			name:   "capture in scheme",
			target: pathtemplate.Target{Scheme: "{a}", Hostname: "example.com", Path: "/"},
		},
		{
			name:   "javascript scheme",
			target: pathtemplate.Target{Scheme: "javascript", Hostname: "example.com", Path: "/"},
		},
		{
			name:   "capture in hostname",
			target: pathtemplate.Target{Scheme: "https", Hostname: "{a}.example.com", Path: "/"},
		},
		{
			name:   "slash in hostname",
			target: pathtemplate.Target{Scheme: "https", Hostname: "evil.com/path", Path: "/"},
		},
		{
			name:   "userinfo in hostname",
			target: pathtemplate.Target{Scheme: "https", Hostname: "user@evil.com", Path: "/"},
		},
		{
			name:   "leading hyphen in hostname",
			target: pathtemplate.Target{Scheme: "https", Hostname: "-evil.com", Path: "/"},
		},
		{
			name:   "relative target path without leading slash",
			target: pathtemplate.Target{Path: "relative/{a}"},
		},
		{
			name:   "protocol-relative target path",
			target: pathtemplate.Target{Path: "//evil.com/{a}"},
		},
		{
			name:    "relative target expanding to protocol-relative URL when multi-segment is empty",
			pattern: "/{host}/{rest=**}",
			target:  pathtemplate.Target{Path: "/{rest}/{host}"},
		},
		{
			name:    "relative target expanding to double slash when multi-segment is empty",
			pattern: "/{host}/{rest=**}",
			target:  pathtemplate.Target{Path: "/{rest}/"},
		},
		{
			name:    "relative target with repeated leading multi-segment before slash",
			pattern: "/{host}/{rest=**}",
			target:  pathtemplate.Target{Path: "/{rest}{rest}/{host}"},
		},
		{
			name:   "query delimiter in target path",
			target: pathtemplate.Target{Path: "/{a}?b=1"},
		},
		{
			name:   "fragment delimiter in target path",
			target: pathtemplate.Target{Path: "/{a}#frag"},
		},
		{
			name:   "leading question mark in target query",
			target: pathtemplate.Target{Path: "/", Query: "?q={a}"},
		},
		{
			name:   "fragment delimiter in target query",
			target: pathtemplate.Target{Path: "/", Query: "q={a}#frag"},
		},
		{
			name:   "leading hash in target fragment",
			target: pathtemplate.Target{Path: "/", Fragment: "#sec"},
		},
		{
			name:   "unknown variable in path",
			target: pathtemplate.Target{Path: "/{missing}"},
		},
		{
			name:   "unknown variable in query",
			target: pathtemplate.Target{Path: "/", Query: "q={missing}"},
		},
		{
			name:   "unknown variable in fragment",
			target: pathtemplate.Target{Path: "/", Fragment: "{missing}"},
		},
		{
			name:   "unclosed brace in target path",
			target: pathtemplate.Target{Path: "/{a"},
		},
		{
			name:   "stray closing brace in target query",
			target: pathtemplate.Target{Path: "/", Query: "q=a}"},
		},
		{
			name:   "nested braces in target fragment",
			target: pathtemplate.Target{Path: "/", Fragment: "{{a}}"},
		},
		{
			name:   "unknown query mode",
			target: pathtemplate.Target{Path: "/", QueryMode: "bogus"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			pattern := testCase.pattern
			if pattern == "" {
				pattern = "/{a}"
			}
			if _, err := pathtemplate.NewMatcher(pathtemplate.Rule{
				Pattern: pattern,
				Target:  testCase.target,
			}); err == nil {
				t.Errorf("NewMatcher succeeded for %s, want error", testCase.name)
			}
		})
	}
}

func TestRelativeTargetMultiSegmentSafeCases(t *testing.T) {
	// Leading multi-segment without a following "/" cannot expand to "//".
	relativeMatcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{host}/{rest=**}",
		Target:  pathtemplate.Target{Path: "/{rest}"},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}
	if got, ok := relativeMatcher.Match("/evil.com/", ""); !ok || got != "/" {
		t.Errorf("Match(/evil.com/) = (%q, %v), want (\"/\", true)", got, ok)
	}
	if got, ok := relativeMatcher.Match("/evil.com/sub/page", ""); !ok || got != "/sub/page" {
		t.Errorf("Match(/evil.com/sub/page) = (%q, %v), want (\"/sub/page\", true)", got, ok)
	}

	// Absolute targets keep static scheme and hostname so "/{rest}/{host}" is not protocol-relative.
	absoluteMatcher, err := pathtemplate.NewMatcher(pathtemplate.Rule{
		Pattern: "/{host}/{rest=**}",
		Target: pathtemplate.Target{
			Scheme:   "https",
			Hostname: "example.com",
			Path:     "/{rest}/{host}",
		},
	})
	if err != nil {
		t.Fatalf("NewMatcher failed for absolute target: %v", err)
	}
	if got, ok := absoluteMatcher.Match("/site/dir", ""); !ok || got != "https://example.com/dir/site" {
		t.Errorf("Match(/site/dir) = (%q, %v), want (\"https://example.com/dir/site\", true)", got, ok)
	}
}
