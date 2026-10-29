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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256 of "a"
const testDigest = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

func TestGenerateProvenanceStatement(t *testing.T) {
	t.Run("should generate a statement with images, files, inputs and timestamps", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "app.tar.gz")
		require.NoError(t, os.WriteFile(file, []byte("a"), 0600))

		payload, err := generateProvenanceStatement(
			[]string{"ghcr.io/org/image@sha256:" + testDigest},
			[]string{file},
			[]string{"target=ociImage", "flags=--impure=true"},
			"2026-10-27T14:00:00+02:00",
			"2026-10-27T12:05:00Z",
		)
		require.NoError(t, err)

		var statement map[string]any
		require.NoError(t, json.Unmarshal(payload, &statement))

		assert.Equal(t, "https://in-toto.io/Statement/v1", statement["_type"])
		assert.Equal(t, dtos.SLSAProvenanceV1PredicateType, statement["predicateType"])
		assert.Equal(t, []any{
			map[string]any{"name": "ghcr.io/org/image", "digest": map[string]any{"sha256": testDigest}},
			map[string]any{"name": "app.tar.gz", "digest": map[string]any{"sha256": testDigest}},
		}, statement["subject"])
		assert.Equal(t, map[string]any{
			"buildDefinition": map[string]any{
				"buildType": dtos.SLSACIWorkflowBuildType,
				// only the first = separates key and value
				"externalParameters": map[string]any{"inputs": map[string]any{"target": "ociImage", "flags": "--impure=true"}},
			},
			"runDetails": map[string]any{
				// timestamps are normalized to UTC
				"metadata": map[string]any{"startedOn": "2026-10-27T12:00:00Z", "finishedOn": "2026-10-27T12:05:00Z"},
			},
		}, statement["predicate"])
	})

	t.Run("should leave out the run details if no timestamp is given", func(t *testing.T) {
		payload, err := generateProvenanceStatement([]string{"ghcr.io/org/image@sha256:" + testDigest}, nil, nil, "", "")
		require.NoError(t, err)

		var statement map[string]any
		require.NoError(t, json.Unmarshal(payload, &statement))
		assert.NotContains(t, statement["predicate"], "runDetails")
	})

	t.Run("should reject invalid input", func(t *testing.T) {
		image := []string{"ghcr.io/org/image@sha256:" + testDigest}
		cases := map[string]struct {
			images    []string
			files     []string
			inputs    []string
			startedOn string
		}{
			"no subject":            {},
			"image without digest":  {images: []string{"ghcr.io/org/image:1.2.3"}},
			"image without name":    {images: []string{"@sha256:" + testDigest}},
			"image with sha512":     {images: []string{"ghcr.io/org/image@sha512:" + testDigest + testDigest}},
			"digest not hex":        {images: []string{"ghcr.io/org/image@sha256:not-hex"}},
			"digest too short":      {images: []string{"ghcr.io/org/image@sha256:ca97"}},
			"file does not exist":   {files: []string{filepath.Join(t.TempDir(), "missing.tar.gz")}},
			"input without value":   {images: image, inputs: []string{"target"}},
			"input without key":     {images: image, inputs: []string{"=ociImage"}},
			"duplicate input":       {images: image, inputs: []string{"target=a", "target=b"}},
			"timestamp not rfc3339": {images: image, startedOn: "2026-10-27 12:00"},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := generateProvenanceStatement(c.images, c.files, c.inputs, c.startedOn, "")
				assert.Error(t, err)
			})
		}
	})
}

func TestSignProvenanceWithToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := hex.EncodeToString(key.D.FillBytes(make([]byte, 32)))

	statement, err := generateProvenanceStatement([]string{"ghcr.io/org/image@sha256:" + testDigest}, nil, []string{"target=ociImage"}, "", "")
	require.NoError(t, err)

	t.Run("should sign the statement with the token key and mark it as self signed", func(t *testing.T) {
		signed, err := signProvenanceWithToken(context.Background(), statement, token)
		require.NoError(t, err)

		var envelope dsse.Envelope
		require.NoError(t, json.Unmarshal(signed, &envelope))
		require.Len(t, envelope.Signatures, 1)
		assert.NotEmpty(t, envelope.Signatures[0].KeyID)

		payload, err := envelope.DecodeB64Payload()
		require.NoError(t, err)
		signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
		require.NoError(t, err)
		digest := sha256.Sum256(dsse.PAE(envelope.PayloadType, payload))
		assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature), "envelope must be signed with the token key")

		var result map[string]any
		require.NoError(t, json.Unmarshal(payload, &result))
		predicate := result["predicate"].(map[string]any)
		assert.Equal(t, dtos.SLSASelfSignedBuilderID, predicate["runDetails"].(map[string]any)["builder"].(map[string]any)["id"])
		assert.Equal(t, map[string]any{"target": "ociImage"}, predicate["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["inputs"])
		assert.Len(t, result["subject"], 1)
	})

	t.Run("should reject other predicate types", func(t *testing.T) {
		_, err := signProvenanceWithToken(context.Background(), []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [{"name": "image", "digest": {"sha256": "`+testDigest+`"}}],
			"predicateType": "https://cyclonedx.org/bom",
			"predicate": {}
		}`), token)
		assert.Error(t, err)
	})
}

func TestSplitCommaSeparated(t *testing.T) {
	assert.Equal(t, []string{"a@sha256:1", "b@sha256:2"}, splitCommaSeparated(" a@sha256:1, b@sha256:2 ,,"))
	assert.Empty(t, splitCommaSeparated(""))
}
