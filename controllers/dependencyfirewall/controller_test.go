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
	"context"
	"strings"
	"testing"
)

func TestCheckNotAllowedPackage(t *testing.T) {
	d := &DependencyProxyController{}

	testCases := []struct {
		name               string
		eco                ecosystem
		path               string
		rules              []string
		expectedBlocked    bool
		expectedReasonPart string
	}{
		{
			name:               "blocks matching package and version",
			eco:                npm,
			path:               "/lodash/-/lodash-4.17.21.tgz",
			rules:              []string{"pkg:npm/lodash@4.17.21"},
			expectedBlocked:    true,
			expectedReasonPart: "pkg:npm/lodash@4.17.21",
		},
		{
			name:               "last matching negate rule allows package",
			eco:                npm,
			path:               "/react/-/react-17.0.0.tgz",
			rules:              []string{"*", "!pkg:npm/react@17.0.0"},
			expectedBlocked:    false,
			expectedReasonPart: "",
		},
		{
			name:               "blocks npm tarball path matching wildcard version rule",
			eco:                npm,
			path:               "/left-pad/-/left-pad-1.3.0.tgz",
			rules:              []string{"pkg:npm/left-pad@*"},
			expectedBlocked:    true,
			expectedReasonPart: "pkg:npm/left-pad@*",
		},
		{
			name:               "returns not blocked for unresolvable package path",
			eco:                npm,
			path:               "/",
			rules:              []string{"*"},
			expectedBlocked:    false,
			expectedReasonPart: "",
		},
		{
			name:               "blocks matching go module prefix",
			eco:                golang,
			path:               "/github.com/some/module/@v/v1.2.3.info",
			rules:              []string{"pkg:go/github.com/some/module*"},
			expectedBlocked:    true,
			expectedReasonPart: "pkg:go/github.com/some/module*",
		},
		{
			name:               "blocks matching pypi simple package",
			eco:                pypi,
			path:               "/simple/requests/",
			rules:              []string{"pkg:pypi/requests*"},
			expectedBlocked:    true,
			expectedReasonPart: "pkg:pypi/requests*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := d.CheckNotAllowedPackage(
				context.Background(),
				tc.eco,
				tc.path,
				DependencyProxyConfigs{Rules: tc.rules},
			)

			if blocked != tc.expectedBlocked {
				t.Fatalf("expected blocked=%v, got blocked=%v (reason=%q)", tc.expectedBlocked, blocked, reason)
			}

			if tc.expectedReasonPart == "" {
				if reason != "" {
					t.Fatalf("expected empty reason, got %q", reason)
				}
				return
			}

			if !strings.Contains(reason, tc.expectedReasonPart) {
				t.Fatalf("expected reason to contain %q, got %q", tc.expectedReasonPart, reason)
			}
		})
	}
}
