// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dependencyfirewall

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pault.ag/go/debian/control"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func debParagraph(values map[string]string) control.Paragraph {
	return control.Paragraph{Values: values}
}

func debRulesController(t *testing.T, metasnapBody string) *DebDependencyProxyController {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(metasnapBody)), Request: r}, nil
	})}
	return NewDebDependencyProxyController(&DependencyProxyController{client: client}, services.NewDebReleaseTimeService(nil, *client))
}

func debRulesConfigs(t *testing.T, expr string) DependencyProxyConfigs {
	rules, err := celrules.CompilePackageRules([]celrules.PackageRule{{Name: "test-rule", Action: celrules.ActionDeny, Expr: expr}})
	require.NoError(t, err)
	return DependencyProxyConfigs{Rules: rules}
}

const curlYoungRule = `pkg.name.startsWith("debian/") && pkg.name.contains("curl") && now() - timestamp(pkg.releasedAt) < duration("168h")`

func TestDebSourceKey(t *testing.T) {
	cases := []struct {
		name     string
		values   map[string]string
		expected string
	}{
		{name: "source equals package", values: map[string]string{"Package": "curl", "Version": "8.14.1-2"}, expected: "curl@8.14.1-2"},
		{name: "source differs from package", values: map[string]string{"Package": "libcurl4t64", "Source": "curl", "Version": "8.14.1-2"}, expected: "curl@8.14.1-2"},
		{name: "binNMU uses source version", values: map[string]string{"Package": "foo", "Source": "foo (1.2-3)", "Version": "1.2-3+b1"}, expected: "foo@1.2-3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, debSourceKey(debParagraph(tc.values)))
		})
	}
}

func TestCheckDebPackages(t *testing.T) {
	d := debRulesController(t, "")
	packages := func(releasedAt time.Time) []shared.DebPackage {
		return []shared.DebPackage{
			{Paragraph: debParagraph(map[string]string{"Package": "bash", "Version": "5.2.37-2"}), ReleasedAt: releasedAt},
			{Paragraph: debParagraph(map[string]string{"Package": "curl", "Version": "8.14.1-2+deb13u6"}), ReleasedAt: releasedAt},
		}
	}
	young := packages(time.Now().Add(-2 * 24 * time.Hour))

	t.Run("blocks young curl only", func(t *testing.T) {
		blocked := d.checkDebPackages(debRulesConfigs(t, curlYoungRule), shared.DebRegistry, "trixie", young)
		assert.Len(t, blocked, 1)
		assert.Contains(t, blocked, 1)
	})

	t.Run("allows old curl", func(t *testing.T) {
		assert.Empty(t, d.checkDebPackages(debRulesConfigs(t, curlYoungRule), shared.DebRegistry, "trixie", packages(time.Now().Add(-10*24*time.Hour))))
	})

	t.Run("unknown release time counts as now", func(t *testing.T) {
		blocked := d.checkDebPackages(debRulesConfigs(t, curlYoungRule), shared.DebRegistry, "trixie", packages(time.Time{}))
		assert.Len(t, blocked, 1)
	})

	t.Run("suite rule blocks everything in security suite", func(t *testing.T) {
		blocked := d.checkDebPackages(debRulesConfigs(t, `pkg.suite.endsWith("-security")`), shared.DebRegistry, "trixie-security", young)
		assert.Len(t, blocked, 2)
	})
}

func TestGroupDebPackages(t *testing.T) {
	packages := []shared.DebPackage{
		{Paragraph: debParagraph(map[string]string{"Package": "bash", "Version": "5.2.37-2"})},
		{Paragraph: debParagraph(map[string]string{"Package": "curl", "Version": "8.14.1-2+deb13u6"})},
		{Paragraph: debParagraph(map[string]string{"Package": "libcurl4t64", "Source": "curl", "Version": "8.14.1-2+deb13u6"})},
	}

	groups := groupDebPackages(packages, map[int]string{1: "blocked"})
	assert.Equal(t, map[string][]int{"curl@8.14.1-2+deb13u6": {1, 2}}, groups)
}

func TestFindDebReplacements(t *testing.T) {
	young := time.Now().Add(-2 * 24 * time.Hour).UTC().Format(shared.MetasnapLayout)
	metasnap := strings.Join([]string{
		"8.14.1-2+deb13u4 trixie main 20260711T103542Z 20260912T022449Z",
		"8.14.1-2+deb13u5 trixie main 20260912T080811Z " + young,
		"8.14.1-2+deb13u6 trixie main " + young + " " + young,
		"8.15.0-1 unstable main 20260901T000000Z 20261001T000000Z",
	}, "\n")
	packages := []shared.DebPackage{
		{Paragraph: debParagraph(map[string]string{"Package": "curl", "Version": "8.14.1-2+deb13u6", "Architecture": "amd64"})},
		{Paragraph: debParagraph(map[string]string{"Package": "libcurl4t64", "Source": "curl", "Version": "8.14.1-2+deb13u6", "Architecture": "amd64"})},
	}
	groups := map[string][]int{"curl@8.14.1-2+deb13u6": {0, 1}}

	t.Run("picks newest allowed version of the same suite", func(t *testing.T) {
		d := debRulesController(t, metasnap)
		result := d.findDebReplacements(t.Context(), debRulesConfigs(t, curlYoungRule), shared.DebRegistry, "debian", "trixie", packages, groups)
		replacement := result["curl@8.14.1-2+deb13u6"]
		assert.True(t, replacement.found)
		assert.Equal(t, "8.14.1-2+deb13u5", replacement.version)
	})

	t.Run("no replacement when every version is blocked", func(t *testing.T) {
		d := debRulesController(t, metasnap)
		result := d.findDebReplacements(t.Context(), debRulesConfigs(t, `pkg.name == "debian/libcurl4t64"`), shared.DebRegistry, "debian", "trixie", packages, groups)
		assert.False(t, result["curl@8.14.1-2+deb13u6"].found)
	})
}
