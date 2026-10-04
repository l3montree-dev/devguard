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

package controllers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clientProvenance = `{
	"_type": "https://in-toto.io/Statement/v1",
	"subject": [{"name": "image", "digest": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}],
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://devguard.org/build/v1",
			"externalParameters": {"dockerfile": "Dockerfile"},
			"internalParameters": {"devguard": {"workloadIdentity": {"project_path": "attacker/repo"}}},
			"resolvedDependencies": [
				{"uri": "git+https://gitlab.opencode.de/l3montree/slsa-test@refs/heads/main", "digest": {"gitCommit": "dae726b903315dd798caaa492d7a7c983a27dc20"}},
				{"uri": "pkg:docker/alpine@3.20", "digest": {"sha256": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"}}
			]
		},
		"runDetails": {
			"builder": {"id": "https://evil.example.com/builder"},
			"metadata": {"invocationId": "forged", "startedOn": "2026-10-02T10:00:00Z"}
		}
	}
}`

func testWorkloadIdentityClaims() *WorkloadIdentityClaims {
	return &WorkloadIdentityClaims{
		Issuer:         "https://gitlab.opencode.de",
		Subject:        "project_path:l3montree/slsa-test:ref_type:branch:ref:main",
		ProjectID:      "13500",
		ProjectPath:    "l3montree/slsa-test",
		JobID:          "3953308",
		RefPath:        "refs/heads/main",
		SHA:            "dae726b903315dd798caaa492d7a7c983a27dc20",
		CIConfigRefURI: "gitlab.opencode.de/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main",
		CIConfigSHA:    "dae726b903315dd798caaa492d7a7c983a27dc20",
	}
}

func TestIncorporateWorkloadIdentity(t *testing.T) {
	t.Run("should overwrite the identity fields with the verified claims and keep the build description", func(t *testing.T) {
		statement, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		require.NoError(t, incorporateWorkloadIdentity(provenance, testWorkloadIdentityClaims()))
		payload, err := marshalProvenanceStatement(statement, provenance)
		require.NoError(t, err)

		var result map[string]any
		require.NoError(t, json.Unmarshal(payload, &result))

		predicate := result["predicate"].(map[string]any)
		buildDefinition := predicate["buildDefinition"].(map[string]any)
		runDetails := predicate["runDetails"].(map[string]any)

		assert.Equal(t, "https://gitlab.opencode.de/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main?iss=https%3A%2F%2Fgitlab.opencode.de", runDetails["builder"].(map[string]any)["id"])
		assert.Equal(t, "https://gitlab.opencode.de/l3montree/slsa-test/-/jobs/3953308", runDetails["metadata"].(map[string]any)["invocationId"])
		assert.Equal(t, "2026-10-02T10:00:00Z", runDetails["metadata"].(map[string]any)["startedOn"])

		workloadIdentity := buildDefinition["internalParameters"].(map[string]any)["devguard"].(map[string]any)["workloadIdentity"].(map[string]any)
		assert.Equal(t, "l3montree/slsa-test", workloadIdentity["project_path"])

		assert.Equal(t, map[string]any{"dockerfile": "Dockerfile"}, buildDefinition["externalParameters"])
		assert.Equal(t, []any{
			map[string]any{"uri": "pkg:docker/alpine@3.20", "digest": map[string]any{"sha256": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"}},
			map[string]any{"uri": "git+https://gitlab.opencode.de/l3montree/slsa-test@refs/heads/main", "digest": map[string]any{"gitCommit": "dae726b903315dd798caaa492d7a7c983a27dc20"}},
		}, buildDefinition["resolvedDependencies"])

		assert.Equal(t, "https://in-toto.io/Statement/v1", result["_type"])
		assert.Len(t, result["subject"], 1)
	})

	t.Run("should reject a source dependency which contradicts the token commit", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		claims := testWorkloadIdentityClaims()
		claims.SHA = "other-commit"

		assert.Error(t, incorporateWorkloadIdentity(provenance, claims))
	})

	t.Run("should reject tokens which are not gitlab id tokens", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		assert.Error(t, incorporateWorkloadIdentity(provenance, &WorkloadIdentityClaims{Issuer: "https://token.actions.githubusercontent.com"}))
	})
}

func TestParseProvenanceStatement(t *testing.T) {
	t.Run("should reject other predicate types", func(t *testing.T) {
		_, _, err := parseProvenanceStatement([]byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{"name": "image", "digest": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}],
			"predicateType": "https://cyclonedx.org/bom",
			"predicate": {}
		}`))
		assert.Error(t, err)
	})

	t.Run("should reject statements without subject", func(t *testing.T) {
		_, _, err := parseProvenanceStatement([]byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [],
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {}
		}`))
		assert.Error(t, err)
	})
}
