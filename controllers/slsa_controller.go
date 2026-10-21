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

// WorkloadIdentityClaims are the claims of a CI workload identity token. The fields cover the
// GitLab CI id_token and the GitHub Actions OIDC token - the claim sets do not overlap, so which
// of them is populated also tells us which build platform issued the token.
// See https://docs.gitlab.com/ci/secrets/id_token_authentication/#token-payload and
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
type WorkloadIdentityClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  any    `json:"aud,omitempty"` // string or []string
	JTI       string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`

	// gitlab
	ProjectID         string `json:"project_id,omitempty"`
	ProjectPath       string `json:"project_path,omitempty"`
	ProjectVisibility string `json:"project_visibility,omitempty"`
	NamespaceID       string `json:"namespace_id,omitempty"`
	NamespacePath     string `json:"namespace_path,omitempty"`

	UserID          string `json:"user_id,omitempty"`
	UserLogin       string `json:"user_login,omitempty"`
	UserEmail       string `json:"user_email,omitempty"`
	UserAccessLevel string `json:"user_access_level,omitempty"`

	PipelineID     string `json:"pipeline_id,omitempty"`
	PipelineSource string `json:"pipeline_source,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	JobSource      string `json:"job_source,omitempty"`
	JobProjectID   string `json:"job_project_id,omitempty"`
	JobProjectPath string `json:"job_project_path,omitempty"`

	RefPath string `json:"ref_path,omitempty"`

	CIConfigRefURI string `json:"ci_config_ref_uri,omitempty"`
	CIConfigSHA    string `json:"ci_config_sha,omitempty"`

	RunnerID int64 `json:"runner_id,omitempty"`

	// github
	Repository           string `json:"repository,omitempty"`
	RepositoryID         string `json:"repository_id,omitempty"`
	RepositoryOwner      string `json:"repository_owner,omitempty"`
	RepositoryOwnerID    string `json:"repository_owner_id,omitempty"`
	RepositoryVisibility string `json:"repository_visibility,omitempty"`

	// the reusable workflow which ran this job, or the entry workflow if the job is not reusable
	JobWorkflowRef string `json:"job_workflow_ref,omitempty"`
	JobWorkflowSHA string `json:"job_workflow_sha,omitempty"`
	WorkflowRef    string `json:"workflow_ref,omitempty"`
	WorkflowSHA    string `json:"workflow_sha,omitempty"`
	Workflow       string `json:"workflow,omitempty"`

	RunID      string `json:"run_id,omitempty"`
	RunNumber  string `json:"run_number,omitempty"`
	RunAttempt string `json:"run_attempt,omitempty"`

	Actor     string `json:"actor,omitempty"`
	ActorID   string `json:"actor_id,omitempty"`
	EventName string `json:"event_name,omitempty"`

	// shared
	Ref          string `json:"ref,omitempty"`
	RefType      string `json:"ref_type,omitempty"`
	RefProtected string `json:"ref_protected,omitempty"`
	SHA          string `json:"sha,omitempty"`

	Environment          string `json:"environment,omitempty"`
	EnvironmentProtected string `json:"environment_protected,omitempty"`

	RunnerEnvironment string `json:"runner_environment,omitempty"`

	// every claim of the verified token, including the ones not mapped above
	Raw map[string]any `json:"-"`
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

// @Summary Sign SLSA build provenance with the verified identity of the CI job
// @Description Verifies the OIDC workload identity token of the CI job with its issuer, writes the verified
// @Description identity into the provenance and signs it. Returns a DSSE envelope, or a sigstore bundle if a
// @Description transparency log is configured.
// @Tags SLSA
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param X-Workload-Identity-Token header string true "OIDC workload identity token of the CI job"
// @Param provenance body object true "in-toto v1 statement with a SLSA v1 provenance predicate"
// @Success 200 {object} object "signed build provenance"
// @Failure 400 {object} object "invalid build provenance"
// @Failure 401 {object} object "missing or invalid workload identity token"
// @Router /slsa/build-provenance [post]
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
		return echo.NewHTTPError(400, fmt.Sprintf("could not parse build provenance: %s", err.Error())).WithInternal(err)
	}

	if err := incorporateWorkloadIdentity(provenance, claims); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not incorporate the workload identity into the build provenance: %s", err.Error())).WithInternal(err)
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
	if err := idToken.Claims(&claims.Raw); err != nil {
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

// builderIdentity is the platform independent view of a workload identity token: everything the
// build platform told us about who ran this build, and from which source.
type builderIdentity struct {
	// the source repository as a git uri, without a ref
	repositoryURI string
	// the full ref the build ran on, e.g. refs/heads/main
	ref string
	// the commit the build ran on
	commit string
	// the build configuration which ran the build - what verifiers pin against
	builderID      string
	builderVersion map[string]string
	// the url of the concrete run
	invocationID string
}

// resolveBuilderIdentity maps the claims of a verified token onto the fields SLSA provenance needs.
// Each build platform has its own claim names, so this is where support for a platform is added.
func resolveBuilderIdentity(claims *WorkloadIdentityClaims) (*builderIdentity, error) {
	issuer := strings.TrimSuffix(claims.Issuer, "/")

	switch {
	case claims.ProjectPath != "" && claims.CIConfigRefURI != "":
		// gitlab: the issuer is the gitlab instance, so the repository lives below it
		repositoryURI := fmt.Sprintf("git+%s/%s", issuer, claims.ProjectPath)
		return &builderIdentity{
			repositoryURI:  repositoryURI,
			ref:            claims.RefPath,
			commit:         claims.SHA,
			builderID:      fmt.Sprintf("https://%s", claims.CIConfigRefURI),
			builderVersion: map[string]string{"ciConfigSha": claims.CIConfigSHA},
			invocationID:   fmt.Sprintf("%s/%s/-/jobs/%s", issuer, claims.ProjectPath, claims.JobID),
		}, nil

	case claims.Repository != "" && claims.JobWorkflowRef != "":
		// github: the issuer is the token service, not the forge, so the forge is derived from it
		forge, err := githubForgeURL(issuer)
		if err != nil {
			return nil, err
		}
		identity := &builderIdentity{
			repositoryURI: fmt.Sprintf("git+%s/%s", forge, claims.Repository),
			ref:           claims.Ref,
			commit:        claims.SHA,
			// job_workflow_ref names the reusable workflow which ran the job - the trusted builder
			builderID:      fmt.Sprintf("%s/%s", forge, claims.JobWorkflowRef),
			builderVersion: map[string]string{"jobWorkflowSha": claims.JobWorkflowSHA},
			invocationID:   fmt.Sprintf("%s/%s/actions/runs/%s", forge, claims.Repository, claims.RunID),
		}
		if claims.RunAttempt != "" {
			identity.invocationID = fmt.Sprintf("%s/attempts/%s", identity.invocationID, claims.RunAttempt)
		}
		return identity, nil
	}

	return nil, fmt.Errorf("unsupported workload identity token: expected the claims of a gitlab id token or a github actions oidc token")
}

// githubForgeURL returns the base url of the github instance which issued the token.
// github.com uses a dedicated token service, github enterprise server issues from its own host.
func githubForgeURL(issuer string) (string, error) {
	if issuer == "https://token.actions.githubusercontent.com" {
		return "https://github.com", nil
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("could not parse issuer %q: %w", issuer, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("issuer %q has no host", issuer)
	}
	return fmt.Sprintf("https://%s", parsed.Host), nil
}

func incorporateWorkloadIdentity(provenance *provenancev1.Provenance, claims *WorkloadIdentityClaims) error {
	identity, err := resolveBuilderIdentity(claims)
	if err != nil {
		return err
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

	// the source repository is taken from the token. A client provided entry for the same repository must not contradict it
	resolvedDependencies := make([]*attestationv1.ResourceDescriptor, 0, len(provenance.BuildDefinition.ResolvedDependencies)+1)
	for _, dependency := range provenance.BuildDefinition.ResolvedDependencies {
		if dependency.Uri == identity.repositoryURI || strings.HasPrefix(dependency.Uri, identity.repositoryURI+"@") {
			if commit, ok := dependency.Digest["gitCommit"]; ok && commit != identity.commit {
				return fmt.Errorf("resolved dependency %q has commit %q but the workload identity token was issued for commit %q", dependency.Uri, commit, identity.commit)
			}
			continue
		}
		resolvedDependencies = append(resolvedDependencies, dependency)
	}
	resolvedDependencies = append(resolvedDependencies, &attestationv1.ResourceDescriptor{
		Uri:    fmt.Sprintf("%s@%s", identity.repositoryURI, identity.ref),
		Digest: map[string]string{"gitCommit": identity.commit},
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
		Id:      fmt.Sprintf("%s?iss=%s", identity.builderID, url.QueryEscape(claims.Issuer)),
		Version: identity.builderVersion,
	}
	provenance.RunDetails.Metadata.InvocationId = identity.invocationID

	return nil
}

func workloadIdentityInternalParameters(claims *WorkloadIdentityClaims) (*structpb.Struct, error) {
	// prefer the raw claims, so claims we do not map are recorded as well
	workloadIdentity := claims.Raw
	if workloadIdentity == nil {
		b, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &workloadIdentity); err != nil {
			return nil, err
		}
	}
	return structpb.NewStruct(map[string]any{
		"devguard": map[string]any{
			"workloadIdentity": workloadIdentity,
		},
	})
}
