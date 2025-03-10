// Copyright 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestDependencyVulnToTableRow(t *testing.T) {
	t.Run("should print normally with 2 strings when providing a namespace", func(t *testing.T) {
		pURL := packageurl.PackageURL{}
		pURL.Type = "npm"
		pURL.Namespace = "Example Namespace"
		pURL.Name = "next"

		cveid := "Example CVEID"
		rawRiskAssessment := 42424.42
		componentFixedVersion := "Example Version"

		v := dependencyVuln.DependencyVulnDTO{}
		v.CVEID = &cveid
		v.RawRiskAssessment = &rawRiskAssessment
		v.ComponentFixedVersion = &componentFixedVersion
		v.State = models.VulnState("Example State")

		clickableLink := "Example Link"

		output := dependencyVulnToTableRow(pURL, v, clickableLink)
		firstValue := fmt.Sprintln(output[0])
		count := strings.Count(firstValue, "/")
		assert.Equal(t, 2, count, "should be equal")

	})
	t.Run("test with empty namespace should result in only 1 slash instead of a double slash", func(t *testing.T) {
		pURL := packageurl.PackageURL{}
		pURL.Type = "npm"
		pURL.Namespace = ""
		pURL.Name = "next"

		cveid := "Example CVEID"
		rawRiskAssessment := 42424.42
		componentFixedVersion := "Example Version"

		v := dependencyVuln.DependencyVulnDTO{}
		v.CVEID = &cveid
		v.RawRiskAssessment = &rawRiskAssessment
		v.ComponentFixedVersion = &componentFixedVersion
		v.State = models.VulnState("Example State")

		clickableLink := "Example Link"

		output := dependencyVulnToTableRow(pURL, v, clickableLink)
		firstValue := fmt.Sprintln(output[0])
		count := strings.Count(firstValue, "/")

		assert.Equal(t, 1, count, "should be equal")

	})

}
func TestSanitizeApiUrl(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/", "https://example.com"},
		{"http://example.com/", "http://example.com"},
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	}

	for _, test := range tests {
		result := sanitizeApiUrl(test.input)
		assert.Equal(t, test.expected, result)
	}
}
