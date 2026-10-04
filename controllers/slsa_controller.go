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
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/golang-lru/v2/expirable"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	rekorapi "github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const workloadIdentityTokenHeader = "X-Workload-Identity-Token"
const inTotoPayloadType = "application/vnd.in-toto+json"

var supportedSigningAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// WorkloadIdentityClaims are the claims of a GitLab CI id_token.
// See https://docs.gitlab.com/ci/secrets/id_token_authentication/#token-payload
type WorkloadIdentityClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  any    `json:"aud"` // string or []string
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`

	ProjectID         string `json:"project_id"`
	ProjectPath       string `json:"project_path"`
	ProjectVisibility string `json:"project_visibility"`
	NamespaceID       string `json:"namespace_id"`
	NamespacePath     string `json:"namespace_path"`

	UserID          string `json:"user_id"`
	UserLogin       string `json:"user_login"`
	UserEmail       string `json:"user_email"`
	UserAccessLevel string `json:"user_access_level"`

	PipelineID     string `json:"pipeline_id"`
	PipelineSource string `json:"pipeline_source"`
	JobID          string `json:"job_id"`
	JobSource      string `json:"job_source"`
	JobProjectID   string `json:"job_project_id"`
	JobProjectPath string `json:"job_project_path"`

	Ref          string `json:"ref"`
	RefType      string `json:"ref_type"`
	RefPath      string `json:"ref_path"`
	RefProtected string `json:"ref_protected"`
	SHA          string `json:"sha"`

	Environment          string `json:"environment,omitempty"`
	EnvironmentProtected string `json:"environment_protected,omitempty"`

	CIConfigRefURI string `json:"ci_config_ref_uri"`
	CIConfigSHA    string `json:"ci_config_sha"`

	RunnerID          int64  `json:"runner_id"`
	RunnerEnvironment string `json:"runner_environment"`
}

type SLSAController struct {
	// empty means every https issuer is accepted
	trustedIssuers []string
	audience       string

	// nil if no signing key could be loaded
	signingKey *provenanceSigningKey
	// nil if no transparency log is configured
	rekorClient *rekorclient.Rekor

	// used to fetch the issuers discovery documents and keys
	httpClient *http.Client

	mu sync.Mutex
	// bounded, since without trusted issuers every client can bring its own issuer
	verifiers *expirable.LRU[string, *oidc.IDTokenVerifier]
}

func NewSLSAController() *SLSAController {
	var trustedIssuers []string
	for issuer := range strings.SplitSeq(os.Getenv("SLSA_OIDC_TRUSTED_ISSUERS"), ",") {
		if issuer = strings.TrimSpace(issuer); issuer != "" {
			trustedIssuers = append(trustedIssuers, issuer)
		}
	}
	if len(trustedIssuers) == 0 {
		slog.Warn("SLSA_OIDC_TRUSTED_ISSUERS is not set. Workload identity tokens from every https issuer are accepted. " +
			"DevGuard only attests what the issuer claimed: the issuer is recorded in the signed provenance at predicate.buildDefinition.internalParameters.devguard.workloadIdentity.iss " +
			"Verifiers MUST check the issuer before trusting predicate.runDetails.builder.id")
	}

	audience := os.Getenv("SLSA_OIDC_AUDIENCE")
	if audience == "" {
		audience = os.Getenv("API_URL")
	}
	if audience == "" {
		slog.Warn("neither SLSA_OIDC_AUDIENCE nor API_URL is set. All workload identity tokens will be rejected")
	}

	signingKey, err := loadProvenanceSigningKey()
	if err != nil {
		slog.Warn("could not load provenance signing key. Build provenance signing is disabled", "err", err)
	}

	var rekorClient *rekorclient.Rekor
	if rekorURL := os.Getenv("SLSA_REKOR_URL"); rekorURL != "" {
		rekorClient, err = rekorapi.GetRekorClient(rekorURL, rekorapi.WithUserAgent("devguard"))
		if err != nil {
			panic(fmt.Errorf("could not create rekor client for SLSA_REKOR_URL %q: %w", rekorURL, err))
		}
	} else {
		slog.Info("SLSA_REKOR_URL is not set. Signed build provenance is not uploaded to a transparency log - verifiers need to skip the transparency log check (e.g. cosign --insecure-ignore-tlog)")
	}

	return &SLSAController{
		trustedIssuers: trustedIssuers,
		audience:       audience,
		signingKey:     signingKey,
		rekorClient:    rekorClient,
		httpClient:     &utils.EgressClient,
		verifiers:      expirable.NewLRU[string, *oidc.IDTokenVerifier](256, nil, time.Hour),
	}
}

type provenanceSigningKey struct {
	envelopeSigner *dsse.EnvelopeSigner
	publicKey      crypto.PublicKey
	publicKeyPEM   []byte
}

func loadProvenanceSigningKey() (*provenanceSigningKey, error) {
	keyPath := devguardSigningKeyPath()
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read signing key %q: %w", keyPath, err)
	}
	key, err := signerverifier.LoadKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse signing key %q: %w", keyPath, err)
	}
	signer, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(key)
	if err != nil {
		return nil, fmt.Errorf("signing key %q is not an ecdsa key: %w", keyPath, err)
	}
	envelopeSigner, err := dsse.NewEnvelopeSigner(signer)
	if err != nil {
		return nil, err
	}
	return &provenanceSigningKey{
		envelopeSigner: envelopeSigner,
		publicKey:      signer.Public(),
		publicKeyPEM:   []byte(key.KeyVal.Public + "\n"),
	}, nil
}

// @Summary Get the public key devguard signs SLSA build provenance with
// @Tags SLSA
// @Produce application/x-pem-file
// @Success 200 {string} string "PEM encoded public key"
// @Router /slsa/public-key [get]
func (s *SLSAController) PublicKey(ctx shared.Context) error {
	if s.signingKey == nil {
		return echo.NewHTTPError(404, "build provenance signing is not configured")
	}
	return ctx.Blob(200, "application/x-pem-file", s.signingKey.publicKeyPEM)
}

func (s *SLSAController) BuildProvenance(ctx shared.Context) error {
	// TODO: remove the hardcoded test token fallback
	token := ctx.Request().Header.Get(workloadIdentityTokenHeader)
	if token == "" {
		return echo.NewHTTPError(401, "missing workload identity token in "+workloadIdentityTokenHeader+" header")
	}
	token = strings.TrimSpace(token)

	if s.signingKey == nil {
		return echo.NewHTTPError(500, "build provenance signing is not configured")
	}

	claims, err := s.verifyWorkloadIdentityToken(ctx.Request().Context(), token)
	if err != nil {
		return echo.NewHTTPError(401, "invalid workload identity token").WithInternal(err)
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, "could not read build provenance").WithInternal(err)
	}

	statement, provenance, err := parseProvenanceStatement(body)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	if err := incorporateWorkloadIdentity(provenance, claims); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	payload, err := marshalProvenanceStatement(statement, provenance)
	if err != nil {
		return echo.NewHTTPError(500, "could not marshal build provenance").WithInternal(err)
	}

	envelope, err := s.signingKey.envelopeSigner.SignPayload(ctx.Request().Context(), inTotoPayloadType, payload)
	if err != nil {
		return echo.NewHTTPError(500, "could not sign build provenance").WithInternal(err)
	}

	if s.rekorClient == nil {
		return ctx.JSON(200, envelope)
	}

	// with a transparency log the response is a sigstore bundle: the envelope plus the proof of its log entry
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return echo.NewHTTPError(500, "could not marshal signed build provenance").WithInternal(err)
	}
	entry, err := cosign.TLogUploadDSSEEnvelope(ctx.Request().Context(), s.rekorClient, envelopeJSON, s.signingKey.publicKeyPEM)
	if err != nil {
		return echo.NewHTTPError(502, "could not upload signed build provenance to the transparency log").WithInternal(err)
	}
	bundle, err := cosignbundle.MakeNewBundle(s.signingKey.publicKey, entry, payload, envelopeJSON, s.signingKey.publicKeyPEM, nil)
	if err != nil {
		return echo.NewHTTPError(500, "could not create sigstore bundle").WithInternal(err)
	}

	return ctx.Blob(200, "application/vnd.dev.sigstore.bundle.v0.3+json", bundle)
}

// verifyWorkloadIdentityToken verifies the signature, issuer, audience and expiry of a CI OIDC token
// (GitHub Actions or GitLab id_tokens) and returns its claims.
func (s *SLSAController) verifyWorkloadIdentityToken(ctx context.Context, rawToken string) (*WorkloadIdentityClaims, error) {
	if s.audience == "" {
		return nil, fmt.Errorf("no audience configured")
	}

	// the issuer is read unverified only to select the matching provider - the verifier checks it again
	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, err
	}
	if len(s.trustedIssuers) > 0 && !slices.Contains(s.trustedIssuers, issuer) {
		return nil, fmt.Errorf("issuer %q is not trusted", issuer)
	}
	if !strings.HasPrefix(issuer, "https://") {
		return nil, fmt.Errorf("issuer %q is not an https url", issuer)
	}

	verifier, err := s.getVerifier(issuer)
	if err != nil {
		return nil, err
	}

	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify token: %w", err)
	}

	var claims WorkloadIdentityClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("could not parse token claims: %w", err)
	}
	return &claims, nil
}

func (s *SLSAController) getVerifier(issuer string) (*oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if verifier, ok := s.verifiers.Get(issuer); ok {
		return verifier, nil
	}

	// not bound to the request context: the provider keeps using this context to refresh the JWKS
	providerCtx := oidc.ClientContext(context.Background(), s.httpClient)
	provider, err := oidc.NewProvider(providerCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("could not discover oidc provider %q: %w", issuer, err)
	}

	verifier := provider.VerifierContext(providerCtx, &oidc.Config{ClientID: s.audience})
	s.verifiers.Add(issuer, verifier)
	return verifier, nil
}

func unverifiedIssuer(rawToken string) (string, error) {
	token, err := jwt.ParseSigned(rawToken, supportedSigningAlgorithms)
	if err != nil {
		return "", fmt.Errorf("could not parse token: %w", err)
	}

	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", fmt.Errorf("could not parse token claims: %w", err)
	}
	return claims.Issuer, nil
}

const slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

// parseProvenanceStatement parses an in-toto v1 statement with a SLSA v1 provenance predicate.
func parseProvenanceStatement(data []byte) (*attestationv1.Statement, *provenancev1.Provenance, error) {
	var statement attestationv1.Statement
	if err := protojson.Unmarshal(data, &statement); err != nil {
		return nil, nil, fmt.Errorf("could not parse in-toto statement: %w", err)
	}
	if err := statement.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid in-toto statement: %w", err)
	}
	if statement.PredicateType != slsaProvenanceV1 {
		return nil, nil, fmt.Errorf("unsupported predicate type %q, expected %q", statement.PredicateType, slsaProvenanceV1)
	}

	predicate, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read predicate: %w", err)
	}
	var provenance provenancev1.Provenance
	if err := protojson.Unmarshal(predicate, &provenance); err != nil {
		return nil, nil, fmt.Errorf("could not parse slsa provenance predicate: %w", err)
	}
	return &statement, &provenance, nil
}

// marshalProvenanceStatement puts the provenance back into the statement and returns the signable payload.
func marshalProvenanceStatement(statement *attestationv1.Statement, provenance *provenancev1.Provenance) ([]byte, error) {
	if err := provenance.Validate(); err != nil {
		return nil, fmt.Errorf("invalid slsa provenance: %w", err)
	}

	predicate, err := protojson.Marshal(provenance)
	if err != nil {
		return nil, err
	}
	statement.Predicate = &structpb.Struct{}
	if err := protojson.Unmarshal(predicate, statement.Predicate); err != nil {
		return nil, err
	}
	return protojson.Marshal(statement)
}

func incorporateWorkloadIdentity(provenance *provenancev1.Provenance, claims *WorkloadIdentityClaims) error {
	// the claim mapping below is gitlab specific
	if claims.ProjectPath == "" || claims.CIConfigRefURI == "" {
		return fmt.Errorf("only gitlab id tokens are supported for now")
	}

	if provenance.BuildDefinition == nil {
		provenance.BuildDefinition = &provenancev1.BuildDefinition{}
	}
	if provenance.RunDetails == nil {
		provenance.RunDetails = &provenancev1.RunDetails{}
	}
	if provenance.RunDetails.Metadata == nil {
		provenance.RunDetails.Metadata = &provenancev1.BuildMetadata{}
	}

	issuer := strings.TrimSuffix(claims.Issuer, "/")
	repositoryURI := fmt.Sprintf("git+%s/%s", issuer, claims.ProjectPath)

	// the source repository is taken from the token. A client provided entry for the same repository must not contradict it
	resolvedDependencies := make([]*attestationv1.ResourceDescriptor, 0, len(provenance.BuildDefinition.ResolvedDependencies)+1)
	for _, dependency := range provenance.BuildDefinition.ResolvedDependencies {
		if dependency.Uri == repositoryURI || strings.HasPrefix(dependency.Uri, repositoryURI+"@") {
			if commit, ok := dependency.Digest["gitCommit"]; ok && commit != claims.SHA {
				return fmt.Errorf("resolved dependency %q has commit %q but the workload identity token was issued for commit %q", dependency.Uri, commit, claims.SHA)
			}
			continue
		}
		resolvedDependencies = append(resolvedDependencies, dependency)
	}
	resolvedDependencies = append(resolvedDependencies, &attestationv1.ResourceDescriptor{
		Uri:    fmt.Sprintf("%s@%s", repositoryURI, claims.RefPath),
		Digest: map[string]string{"gitCommit": claims.SHA},
	})
	provenance.BuildDefinition.ResolvedDependencies = resolvedDependencies

	// internal parameters are set by the build platform - which is us. Never keep client provided values.
	internalParameters, err := workloadIdentityInternalParameters(claims)
	if err != nil {
		return err
	}
	provenance.BuildDefinition.InternalParameters = internalParameters

	// the builder identity is what verifiers check against - e.g. "is this a devguard ci component"
	// the issuer is part of it, since the builder is only as trustworthy as the issuer claiming it
	provenance.RunDetails.Builder = &provenancev1.Builder{
		Id: fmt.Sprintf("https://%s?iss=%s", claims.CIConfigRefURI, url.QueryEscape(claims.Issuer)),
		Version: map[string]string{
			"ciConfigSha": claims.CIConfigSHA,
		},
	}
	provenance.RunDetails.Metadata.InvocationId = fmt.Sprintf("%s/%s/-/jobs/%s", issuer, claims.ProjectPath, claims.JobID)

	return nil
}

func workloadIdentityInternalParameters(claims *WorkloadIdentityClaims) (*structpb.Struct, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var workloadIdentity map[string]any
	if err := json.Unmarshal(b, &workloadIdentity); err != nil {
		return nil, err
	}
	return structpb.NewStruct(map[string]any{
		"devguard": map[string]any{
			"workloadIdentity": workloadIdentity,
		},
	})
}
