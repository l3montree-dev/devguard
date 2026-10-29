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

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientProvenance forges every field the build platform owns - only the subject, the inputs and the timestamps may survive
const clientProvenance = `{
	"_type": "https://in-toto.io/Statement/v1",
	"subject": [{"name": "image", "digest": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}],
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://evil.example.com/build/v1",
			"externalParameters": {
				"inputs": {"target": "ociImage"},
				"workflow": {"repository": "https://evil.example.com/repo", "path": "build.yml", "ref": "refs/heads/main"}
			},
			"internalParameters": {"devguard": {"workloadIdentity": {"project_path": "attacker/repo"}}},
			"resolvedDependencies": [
				{"uri": "git+https://gitlab.opencode.de/l3montree/slsa-test@refs/heads/main", "digest": {"gitCommit": "0000000000000000000000000000000000000000"}},
				{"uri": "pkg:docker/alpine@3.20", "digest": {"sha256": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"}}
			]
		},
		"runDetails": {
			"builder": {"id": "https://evil.example.com/builder"},
			"metadata": {"invocationId": "forged", "startedOn": "2026-10-02T10:00:00Z", "finishedOn": "2026-10-02T10:05:00Z"},
			"byproducts": [{"uri": "forged-log"}]
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
		UserID:         "42",
		UserLogin:      "jane",
		UserEmail:      "jane@example.com",
		RefPath:        "refs/heads/main",
		SHA:            "dae726b903315dd798caaa492d7a7c983a27dc20",
		CIConfigRefURI: "gitlab.opencode.de/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main",
		CIConfigSHA:    "dae726b903315dd798caaa492d7a7c983a27dc20",
	}
}

func testGithubClaims() *WorkloadIdentityClaims {
	return &WorkloadIdentityClaims{
		Issuer:          "https://token.actions.githubusercontent.com",
		Subject:         "repo:l3montree-dev/slsa-test:ref:refs/heads/main",
		Repository:      "l3montree-dev/slsa-test",
		RepositoryOwner: "l3montree-dev",
		JobWorkflowRef:  "l3montree-dev/trusted-builder/.github/workflows/build.yml@refs/heads/main",
		JobWorkflowSHA:  "8d1f0a2b6c4e9f3a5d7b1c0e2f4a6b8d0c2e4f68",
		WorkflowRef:     "l3montree-dev/slsa-test/.github/workflows/release.yml@refs/heads/main",
		Actor:           "jane",
		ActorID:         "4711",
		Ref:             "refs/heads/main",
		SHA:             "dae726b903315dd798caaa492d7a7c983a27dc20",
		RunID:           "17422331122",
		RunAttempt:      "1",
	}
}

// incorporateIntoClientProvenance runs incorporateWorkloadIdentity on clientProvenance and returns the signable statement as map
func incorporateIntoClientProvenance(t *testing.T, claims *WorkloadIdentityClaims) map[string]any {
	statement, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
	require.NoError(t, err)

	require.NoError(t, incorporateWorkloadIdentity(provenance, claims))
	payload, err := marshalProvenanceStatement(statement, provenance)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(payload, &result))
	return result
}

func TestIncorporateWorkloadIdentity(t *testing.T) {
	t.Run("should set every platform field from the claims and only keep subjects, inputs and timestamps from the client", func(t *testing.T) {
		result := incorporateIntoClientProvenance(t, testWorkloadIdentityClaims())

		predicate := result["predicate"].(map[string]any)
		buildDefinition := predicate["buildDefinition"].(map[string]any)

		assert.Equal(t, dtos.SLSACIWorkflowBuildType, buildDefinition["buildType"])
		assert.Equal(t, map[string]any{
			"workflow": map[string]any{
				"repository": "https://gitlab.opencode.de/l3montree/slsa-test",
				"path":       ".gitlab-ci.yml",
				"ref":        "refs/heads/main",
			},
			"inputs": map[string]any{"target": "ociImage"},
		}, buildDefinition["externalParameters"])
		assert.Equal(t, []any{
			map[string]any{"uri": "git+https://gitlab.opencode.de/l3montree/slsa-test@refs/heads/main", "digest": map[string]any{"gitCommit": "dae726b903315dd798caaa492d7a7c983a27dc20"}},
		}, buildDefinition["resolvedDependencies"])

		assert.Equal(t, map[string]any{
			"builder": map[string]any{
				"id":      "https://gitlab.opencode.de/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main",
				"version": map[string]any{"ciConfigSha": "dae726b903315dd798caaa492d7a7c983a27dc20"},
			},
			"metadata": map[string]any{
				"invocationId": "https://gitlab.opencode.de/l3montree/slsa-test/-/jobs/3953308",
				"startedOn":    "2026-10-02T10:00:00Z",
				"finishedOn":   "2026-10-02T10:05:00Z",
			},
		}, predicate["runDetails"])

		assert.Equal(t, "https://in-toto.io/Statement/v1", result["_type"])
		assert.Len(t, result["subject"], 1)
	})

	t.Run("should only record non personal claims", func(t *testing.T) {
		result := incorporateIntoClientProvenance(t, testWorkloadIdentityClaims())

		buildDefinition := result["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
		workloadIdentity := buildDefinition["internalParameters"].(map[string]any)["devguard"].(map[string]any)["workloadIdentity"].(map[string]any)

		assert.Equal(t, "l3montree/slsa-test", workloadIdentity["project_path"])
		assert.Equal(t, "https://gitlab.opencode.de", workloadIdentity["iss"])
		assert.NotContains(t, workloadIdentity, "user_id")
		assert.NotContains(t, workloadIdentity, "user_login")
		assert.NotContains(t, workloadIdentity, "user_email")
	})

	t.Run("should only record raw claims which are allowed", func(t *testing.T) {
		claims := testGithubClaims()
		claims.Raw = map[string]any{"iss": claims.Issuer, "repository": claims.Repository, "actor": "jane", "actor_id": "4711", "jti": "1", "exp": 1.0}

		internalParameters, err := workloadIdentityInternalParameters(claims)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"iss": claims.Issuer, "repository": claims.Repository},
			internalParameters.AsMap()["devguard"].(map[string]any)["workloadIdentity"])
	})

	t.Run("should reject a gitlab token claiming the ci config of another instance", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		claims := testWorkloadIdentityClaims()
		claims.Issuer = "https://evil.example.com"
		assert.Error(t, incorporateWorkloadIdentity(provenance, claims))

		// a host which only starts with the issuer host is another instance as well
		claims.Issuer = "https://gitlab.open"
		assert.Error(t, incorporateWorkloadIdentity(provenance, claims))
	})

	t.Run("should accept a gitlab instance served below a path", func(t *testing.T) {
		claims := testWorkloadIdentityClaims()
		claims.Issuer = "https://example.com/gitlab"
		claims.CIConfigRefURI = "example.com/gitlab/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main"

		result := incorporateIntoClientProvenance(t, claims)

		builder := result["predicate"].(map[string]any)["runDetails"].(map[string]any)["builder"].(map[string]any)
		assert.Equal(t, "https://example.com/gitlab/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main", builder["id"])
	})

	t.Run("should map github actions claims onto the reusable workflow which ran the job", func(t *testing.T) {
		result := incorporateIntoClientProvenance(t, testGithubClaims())

		predicate := result["predicate"].(map[string]any)
		buildDefinition := predicate["buildDefinition"].(map[string]any)
		runDetails := predicate["runDetails"].(map[string]any)
		builder := runDetails["builder"].(map[string]any)

		assert.Equal(t, "https://github.com/l3montree-dev/trusted-builder/.github/workflows/build.yml@refs/heads/main", builder["id"])
		assert.Equal(t, map[string]any{"jobWorkflowSha": "8d1f0a2b6c4e9f3a5d7b1c0e2f4a6b8d0c2e4f68"}, builder["version"])
		assert.Equal(t, "https://github.com/l3montree-dev/slsa-test/actions/runs/17422331122/attempts/1", runDetails["metadata"].(map[string]any)["invocationId"])

		assert.Equal(t, map[string]any{
			"repository": "https://github.com/l3montree-dev/slsa-test",
			"path":       ".github/workflows/release.yml",
			"ref":        "refs/heads/main",
		}, buildDefinition["externalParameters"].(map[string]any)["workflow"])
		assert.Equal(t, []any{
			map[string]any{"uri": "git+https://github.com/l3montree-dev/slsa-test@refs/heads/main", "digest": map[string]any{"gitCommit": "dae726b903315dd798caaa492d7a7c983a27dc20"}},
		}, buildDefinition["resolvedDependencies"])

		workloadIdentity := buildDefinition["internalParameters"].(map[string]any)["devguard"].(map[string]any)["workloadIdentity"].(map[string]any)
		assert.NotContains(t, workloadIdentity, "actor")
		assert.NotContains(t, workloadIdentity, "actor_id")
	})

	t.Run("should derive the forge from the issuer of a github enterprise server token", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		require.NoError(t, incorporateWorkloadIdentity(provenance, &WorkloadIdentityClaims{
			Issuer:         "https://github.example.com/_services/token",
			Repository:     "org/repo",
			JobWorkflowRef: "org/trusted/.github/workflows/build.yml@refs/heads/main",
			WorkflowRef:    "org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			Ref:            "refs/tags/v1.0.0",
			SHA:            "dae726b903315dd798caaa492d7a7c983a27dc20",
			RunID:          "42",
		}))

		assert.Equal(t, "https://github.example.com/org/trusted/.github/workflows/build.yml@refs/heads/main", provenance.RunDetails.Builder.Id)
		assert.Equal(t, "https://github.example.com/org/repo/actions/runs/42", provenance.RunDetails.Metadata.InvocationId)
		assert.Equal(t, "https://github.example.com/org/repo", provenance.BuildDefinition.ExternalParameters.AsMap()["workflow"].(map[string]any)["repository"])
	})

	t.Run("should build the provenance if the client sent no build definition and no run details", func(t *testing.T) {
		statement, provenance, err := parseProvenanceStatement([]byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{"name": "image", "digest": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}],
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {}
		}`))
		require.NoError(t, err)

		require.NoError(t, incorporateWorkloadIdentity(provenance, testWorkloadIdentityClaims()))
		_, err = marshalProvenanceStatement(statement, provenance)
		require.NoError(t, err)

		assert.NotContains(t, provenance.BuildDefinition.ExternalParameters.AsMap(), "inputs")
		assert.Nil(t, provenance.RunDetails.Metadata.StartedOn)
	})

	t.Run("should reject inputs which are not an object", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{"name": "image", "digest": {"sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}}],
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {"buildDefinition": {"externalParameters": {"inputs": "ociImage"}}}
		}`))
		require.NoError(t, err)

		assert.Error(t, incorporateWorkloadIdentity(provenance, testWorkloadIdentityClaims()))
	})

	t.Run("should reject tokens which belong to no supported build platform", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		assert.Error(t, incorporateWorkloadIdentity(provenance, &WorkloadIdentityClaims{Issuer: "https://token.actions.githubusercontent.com"}))
	})

	t.Run("should reject github tokens without workflow_ref", func(t *testing.T) {
		_, provenance, err := parseProvenanceStatement([]byte(clientProvenance))
		require.NoError(t, err)

		claims := testGithubClaims()
		claims.WorkflowRef = ""
		assert.Error(t, incorporateWorkloadIdentity(provenance, claims))
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
