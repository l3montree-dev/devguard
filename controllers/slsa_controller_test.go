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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v4"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAudience = "http://localhost:8080"

// testOIDCIssuer is a minimal OIDC issuer serving discovery and JWKS like gitlab does for CI id_tokens.
type testOIDCIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newTestOIDCIssuer(t *testing.T) *testOIDCIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuer := &testOIDCIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.server.URL,
			"jwks_uri":                              issuer.server.URL + "/oauth/discovery/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/oauth/discovery/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}}})
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testOIDCIssuer) host() string {
	return strings.TrimPrefix(i.server.URL, "https://")
}

func (i *testOIDCIssuer) token(t *testing.T, audience string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	now := time.Now()
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":               i.server.URL,
		"sub":               "project_path:l3montree/slsa-test:ref_type:branch:ref:main",
		"aud":               audience,
		"iat":               now.Unix(),
		"nbf":               now.Unix(),
		"exp":               now.Add(5 * time.Minute).Unix(),
		"jti":               "91fa9103-16d5-43e1-9ece-2ceef1926f48",
		"project_id":        "13500",
		"project_path":      "l3montree/slsa-test",
		"job_id":            "3953308",
		"ref":               "main",
		"ref_path":          "refs/heads/main",
		"sha":               "dae726b903315dd798caaa492d7a7c983a27dc20",
		"ci_config_ref_uri": i.host() + "/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main",
		"ci_config_sha":     "dae726b903315dd798caaa492d7a7c983a27dc20",
		"runner_id":         1126,
	}).Serialize()
	require.NoError(t, err)
	return token
}

// fakeRekor records the uploaded log entries and answers with a minimal, unsigned log entry.
type fakeRekor struct {
	server *httptest.Server

	mu      sync.Mutex
	uploads [][]byte
}

func newFakeRekor(t *testing.T) *fakeRekor {
	rekor := &fakeRekor{}
	rekor.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rekor.mu.Lock()
		rekor.uploads = append(rekor.uploads, body)
		rekor.mu.Unlock()

		// the uploaded entry is echoed back as log entry body. Hashes, proof and timestamps are dummies
		hash := hex.EncodeToString(make([]byte, sha256.Size))
		logIndex, integratedTime, treeSize, treeIndex := int64(42), time.Now().Unix(), int64(1), int64(0)
		checkpoint := "fake-rekor"

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.LogEntry{
			hash: models.LogEntryAnon{
				Body:           base64.StdEncoding.EncodeToString(body),
				IntegratedTime: &integratedTime,
				LogID:          &hash,
				LogIndex:       &logIndex,
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: &checkpoint,
						Hashes:     []string{},
						LogIndex:   &treeIndex,
						RootHash:   &hash,
						TreeSize:   &treeSize,
					},
				},
			},
		})
	}))
	t.Cleanup(rekor.server.Close)
	return rekor
}

func (r *fakeRekor) uploadedEntries() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.uploads...)
}

func newTestSLSAController(t *testing.T, issuer *testOIDCIssuer, rekorURL string) (*SLSAController, *ecdsa.PublicKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "devguard-signing-key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600))

	t.Setenv("SLSA_PRIVATE_KEY_PATH", keyPath)
	t.Setenv("SLSA_OIDC_AUDIENCE", testAudience)
	t.Setenv("SLSA_OIDC_TRUSTED_ISSUERS", "")
	t.Setenv("SLSA_REKOR_URL", rekorURL)

	controller := NewSLSAController()
	// trusts the self signed certificate of the test issuer
	controller.httpClient = issuer.server.Client()
	return controller, &key.PublicKey
}

func callBuildProvenance(controller *SLSAController, token string) (*httptest.ResponseRecorder, error) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/slsa/build-provenance/", strings.NewReader(clientProvenance))
	req.Header.Set(workloadIdentityTokenHeader, token)
	rec := httptest.NewRecorder()
	return rec, controller.BuildProvenance(echo.New().NewContext(req, rec))
}

func httpErrorCode(err error) int {
	var httpErr *echo.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Code
	}
	return 0
}

// assertProvenanceIdentity checks the signed statement carries the identity of the test issuer.
func assertProvenanceIdentity(t *testing.T, issuer *testOIDCIssuer, payload []byte) {
	var statement map[string]any
	require.NoError(t, json.Unmarshal(payload, &statement))

	predicate := statement["predicate"].(map[string]any)
	builder := predicate["runDetails"].(map[string]any)["builder"].(map[string]any)
	assert.Equal(t, "https://"+issuer.host()+"/l3montree/slsa-test//.gitlab-ci.yml@refs/heads/main?iss="+url.QueryEscape(issuer.server.URL), builder["id"])

	workloadIdentity := predicate["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)["devguard"].(map[string]any)["workloadIdentity"].(map[string]any)
	assert.Equal(t, issuer.server.URL, workloadIdentity["iss"])
	assert.Equal(t, "l3montree/slsa-test", workloadIdentity["project_path"])
}

func TestBuildProvenance(t *testing.T) {
	t.Run("should return a signed dsse envelope if no transparency log is configured", func(t *testing.T) {
		issuer := newTestOIDCIssuer(t)
		controller, publicKey := newTestSLSAController(t, issuer, "")

		rec, err := callBuildProvenance(controller, issuer.token(t, testAudience))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var envelope dsse.Envelope
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
		assert.Equal(t, inTotoPayloadType, envelope.PayloadType)

		payload, err := envelope.DecodeB64Payload()
		require.NoError(t, err)
		require.Len(t, envelope.Signatures, 1)
		signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
		require.NoError(t, err)
		digest := sha256.Sum256(dsse.PAE(envelope.PayloadType, payload))
		assert.True(t, ecdsa.VerifyASN1(publicKey, digest[:], signature), "envelope must be signed with the devguard key")

		assertProvenanceIdentity(t, issuer, payload)
	})

	t.Run("should upload the envelope to the transparency log and return a sigstore bundle", func(t *testing.T) {
		issuer := newTestOIDCIssuer(t)
		rekor := newFakeRekor(t)
		controller, _ := newTestSLSAController(t, issuer, rekor.server.URL)

		rec, err := callBuildProvenance(controller, issuer.token(t, testAudience))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/vnd.dev.sigstore.bundle.v0.3+json", rec.Header().Get("Content-Type"))

		// exactly one dsse entry with the signed envelope and the devguard public key was uploaded
		uploads := rekor.uploadedEntries()
		require.Len(t, uploads, 1)
		var upload struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
			Spec       struct {
				ProposedContent struct {
					Envelope  string   `json:"envelope"`
					Verifiers [][]byte `json:"verifiers"`
				} `json:"proposedContent"`
			} `json:"spec"`
		}
		require.NoError(t, json.Unmarshal(uploads[0], &upload))
		assert.Equal(t, "dsse", upload.Kind)
		assert.Equal(t, "0.0.1", upload.APIVersion)
		assert.Equal(t, [][]byte{controller.signingKey.publicKeyPEM}, upload.Spec.ProposedContent.Verifiers)

		var uploadedEnvelope dsse.Envelope
		require.NoError(t, json.Unmarshal([]byte(upload.Spec.ProposedContent.Envelope), &uploadedEnvelope))
		uploadedPayload, err := uploadedEnvelope.DecodeB64Payload()
		require.NoError(t, err)

		var bundle struct {
			MediaType            string `json:"mediaType"`
			VerificationMaterial struct {
				PublicKey struct {
					Hint string `json:"hint"`
				} `json:"publicKey"`
				TlogEntries []struct {
					LogIndex    string `json:"logIndex"`
					KindVersion struct {
						Kind    string `json:"kind"`
						Version string `json:"version"`
					} `json:"kindVersion"`
					InclusionProof struct {
						TreeSize string `json:"treeSize"`
					} `json:"inclusionProof"`
				} `json:"tlogEntries"`
			} `json:"verificationMaterial"`
			DsseEnvelope struct {
				Payload     []byte `json:"payload"`
				PayloadType string `json:"payloadType"`
			} `json:"dsseEnvelope"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &bundle))

		assert.Equal(t, "application/vnd.dev.sigstore.bundle.v0.3+json", bundle.MediaType)
		assert.NotEmpty(t, bundle.VerificationMaterial.PublicKey.Hint)
		require.Len(t, bundle.VerificationMaterial.TlogEntries, 1)
		assert.Equal(t, "42", bundle.VerificationMaterial.TlogEntries[0].LogIndex)
		assert.Equal(t, "dsse", bundle.VerificationMaterial.TlogEntries[0].KindVersion.Kind)
		assert.Equal(t, "1", bundle.VerificationMaterial.TlogEntries[0].InclusionProof.TreeSize)
		assert.Equal(t, inTotoPayloadType, bundle.DsseEnvelope.PayloadType)
		// the bundle contains what was logged
		assert.Equal(t, uploadedPayload, bundle.DsseEnvelope.Payload)

		assertProvenanceIdentity(t, issuer, bundle.DsseEnvelope.Payload)
	})

	t.Run("should reject tokens issued for another audience", func(t *testing.T) {
		issuer := newTestOIDCIssuer(t)
		controller, _ := newTestSLSAController(t, issuer, "")

		_, err := callBuildProvenance(controller, issuer.token(t, "sigstore"))
		assert.Equal(t, http.StatusUnauthorized, httpErrorCode(err))
	})

	t.Run("should reject issuers which are not trusted if trusted issuers are configured", func(t *testing.T) {
		issuer := newTestOIDCIssuer(t)
		controller, _ := newTestSLSAController(t, issuer, "")
		controller.trustedIssuers = []string{"https://gitlab.opencode.de"}

		_, err := callBuildProvenance(controller, issuer.token(t, testAudience))
		assert.Equal(t, http.StatusUnauthorized, httpErrorCode(err))
	})

	t.Run("should not sign if the transparency log rejects the entry", func(t *testing.T) {
		issuer := newTestOIDCIssuer(t)
		rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		t.Cleanup(rekor.Close)
		controller, _ := newTestSLSAController(t, issuer, rekor.URL)

		_, err := callBuildProvenance(controller, issuer.token(t, testAudience))
		assert.Equal(t, http.StatusBadGateway, httpErrorCode(err))
	})
}
