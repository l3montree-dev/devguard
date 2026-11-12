package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/yaronf/httpsign"
)

type PatService struct {
	patRepository  shared.PersonalAccessTokenRepository
	adminPubKey    ecdsa.PublicKey
	adminKeyLoaded bool
}

var _ shared.PersonalAccessTokenService = (*PatService)(nil) // Ensure PatService implements shared.PersonalAccessTokenService interface

func NewPatService(repository shared.PersonalAccessTokenRepository) *PatService {
	// read the admin public key from the environment variable and convert it to ecdsa.PublicKey
	// the public key is expected to be in hex format (X and Y concatenated)
	adminPubKeyPath := os.Getenv("INSTANCE_ADMIN_PUB_KEY_PATH")
	if adminPubKeyPath == "" {
		slog.Warn("no admin public key provided, admin token authentication will not work")
		return &PatService{
			patRepository: repository,
		}
	}

	// read the admin public key from the file
	adminPubKeyHexBytes, err := os.ReadFile(adminPubKeyPath)
	if err != nil {
		slog.Error("could not read admin public key from file", "err", err)
		return &PatService{
			patRepository: repository,
		}
	}

	// TrimSpace so that trailing newlines from editors do not corrupt the hex parsing.
	adminPubKey, err := HexPubKeyToECDSA(strings.TrimSpace(string(adminPubKeyHexBytes)))
	if err != nil {
		slog.Error("could not parse admin public key — admin authentication will not work", "err", err)
		return &PatService{
			patRepository: repository,
		}
	}
	return &PatService{
		patRepository:  repository,
		adminPubKey:    adminPubKey,
		adminKeyLoaded: true,
	}
}

func ownerToFields(o dtos.TokenOwner) (userID *uuid.UUID, orgID *uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) {
	switch shared.SessionActor(o.Type) {
	case shared.SessionActorUser:
		return &o.ID, nil, nil, nil
	case shared.SessionActorOrg:
		return nil, &o.ID, nil, nil
	case shared.SessionActorProject:
		return nil, nil, &o.ID, nil
	case shared.SessionActorAsset:
		return nil, nil, nil, &o.ID
	}
	return nil, nil, nil, nil
}

func (p *PatService) ToModel(ctx context.Context, request dtos.PatCreateRequest, owner dtos.TokenOwner) (models.PAT, string, error) {
	if !utils.ContainsAll(dtos.AllowedScopes, strings.Fields(request.Scopes)) {
		return models.PAT{}, "", fmt.Errorf("invalid scopes: %s", request.Scopes)
	}

	expiry := new(time.Unix(request.ExpiryDateUnix, 0))

	userID, orgID, projectID, assetID := ownerToFields(owner)

	if request.IsSymmetric() {
		cleartext, hash, err := generateBearerToken()
		if err != nil {
			return models.PAT{}, "", fmt.Errorf("could not generate bearer token: %w", err)
		}
		return models.PAT{
			UserID:          userID,
			OrgID:           orgID,
			ProjectID:       projectID,
			AssetID:         assetID,
			Description:     request.Description,
			Scopes:          request.Scopes,
			BearerTokenHash: &hash,
			ExpiryDate:      expiry,
		}, cleartext, nil
	}

	if err := validatePubKey(*request.PubKey); err != nil {
		return models.PAT{}, "", fmt.Errorf("invalid public key: %w", err)
	}
	fingerprint, err := pubKeyToFingerprint(*request.PubKey)
	if err != nil {
		return models.PAT{}, "", fmt.Errorf("could not derive fingerprint from public key: %w", err)
	}

	return models.PAT{
		UserID:      userID,
		OrgID:       orgID,
		ProjectID:   projectID,
		AssetID:     assetID,
		Description: request.Description,
		Scopes:      request.Scopes,
		PubKey:      request.PubKey,
		Fingerprint: &fingerprint,
		ExpiryDate:  expiry,
	}, "", nil
}

var BearerTokenPrefix = "dvg_"

// generateBearerToken creates a random dvg_-prefixed token and returns the cleartext and its hash.
func generateBearerToken() (cleartext, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	cleartext = BearerTokenPrefix + hex.EncodeToString(raw)
	return cleartext, utils.HashString(cleartext), nil
}

// validatePubKey checks that pubKey is a valid hex-encoded P256 public key (128 hex chars).
func validatePubKey(pubKey string) error {
	decoded, err := hex.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("public key must be hex-encoded: %w", err)
	}
	if len(decoded) != 64 {
		return fmt.Errorf("public key must be 64 bytes (got %d)", len(decoded))
	}
	uncompressed := append([]byte{0x04}, decoded...)
	_, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	return nil
}

func pubKeyToFingerprint(pubKey string) (string, error) {
	fingerprint := sha256.New()
	_, err := fingerprint.Write([]byte(pubKey))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(fingerprint.Sum(nil)), nil
}

func HexPubKeyToECDSA(hexPubKey string) (ecdsa.PublicKey, error) {

	decodedPubKey, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("could not decode hexPubKey: %v", err)
	}
	if len(decodedPubKey) != 64 {
		return ecdsa.PublicKey{}, fmt.Errorf("invalid public key length: expected 64 bytes, got %d", len(decodedPubKey))
	}
	uncompressed := append([]byte{0x04}, decodedPubKey...)
	pubKeyECDSA, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("could not parse hexPubKey: %v", err)
	}
	return *pubKeyECDSA, nil
}

func GetPubKeyBytes(pubKey ecdsa.PublicKey) ([]byte, error) {
	uncompressed, err := pubKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("could not get public key bytes: %v", err)
	}
	return uncompressed[1:], nil // skip the 0x04 prefix for uncompressed keys
}

func HexTokenToECDSA(hexToken string) (ecdsa.PrivateKey, ecdsa.PublicKey, error) {
	privKeyDecoded, err := hex.DecodeString(hexToken)
	if err != nil {
		return ecdsa.PrivateKey{}, ecdsa.PublicKey{}, fmt.Errorf("could not decode hexPrivKey: %v", err)
	}

	privKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), privKeyDecoded)
	if err != nil {
		return ecdsa.PrivateKey{}, ecdsa.PublicKey{}, fmt.Errorf("could not parse hexPrivKey: %v", err)
	}
	return *privKey, privKey.PublicKey, nil
}

func signedFields() httpsign.Fields {
	return httpsign.Headers("@method", "@path", "@query", "content-digest")
}

const (
	signatureMaxAge    = 10 * time.Second
	signatureClockSkew = 2 * time.Second
)

func signConfig() *httpsign.SignConfig {
	return httpsign.NewSignConfig().
		SignCreated(true).
		SetExpiresAfter(int64(signatureMaxAge.Seconds()))
}

func verifyConfig() *httpsign.VerifyConfig {
	return httpsign.NewVerifyConfig().
		SetVerifyCreated(true).
		SetNotOlderThan(signatureMaxAge).
		SetNotNewerThan(signatureClockSkew).
		SetRejectExpired(true)
}

func AuthenticateRequestWithToken(token string, req *http.Request) error {
	if token == "" {
		return fmt.Errorf("token is empty")
	}

	if !strings.HasPrefix(token, BearerTokenPrefix) {
		// assume it's a hex-encoded private key
		return signRequest(token, req)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func signRequest(hexPrivKey string, req *http.Request) error {
	privKey, pubKey, err := HexTokenToECDSA(hexPrivKey)
	if err != nil {
		return fmt.Errorf("could not convert hex token to ECDSA: %v", err)
	}

	pubKeyBytes, err := GetPubKeyBytes(pubKey)
	if err != nil {
		return fmt.Errorf("could not get public key bytes: %v", err)
	}

	pubKeyString := hex.EncodeToString(pubKeyBytes)

	fingerprint, err := pubKeyToFingerprint(pubKeyString)
	if err != nil {
		return err
	}

	signer, _ := httpsign.NewP256Signer(privKey, signConfig(), signedFields())

	req.Header.Set("X-Fingerprint", fingerprint)

	digest, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
	if err != nil {
		return fmt.Errorf("could not generate content digest header: %v", err)
	}
	req.Header.Set("Content-Digest", digest)
	signatureInput, signature, err := httpsign.SignRequest("sig77", *signer, req)
	if err != nil {
		return fmt.Errorf("could not sign request: %v", err)
	}

	req.Header.Set("Signature-Input", signatureInput)
	req.Header.Set("Signature", signature)

	return nil
}

func (p *PatService) VerifyAPIToken(ctx context.Context, token string) (shared.AuthSession, error) {
	if token == "" {
		return nil, fmt.Errorf("invalid token format")
	}

	pat, err := p.patRepository.GetByBearerTokenHash(ctx, nil, utils.HashString(token))
	if err != nil {
		return nil, fmt.Errorf("could not verify bearer token: %w", err)
	}
	if pat.IsExpired() {
		return nil, fmt.Errorf("bearer token has expired")
	}

	if err := p.patRepository.MarkAsLastUsedNowByID(ctx, nil, pat.ID); err != nil {
		slog.Warn("could not mark pat as last used", "err", err)
	}

	return patToSession(pat)
}

func patToSession(pat models.PAT) (shared.AuthSession, error) {
	switch true {
	case pat.UserID != nil:
		return shared.NewPATSession(pat.UserID.String(), pat.Description, shared.SessionActorUser, strings.Fields(pat.Scopes)), nil
	case pat.OrgID != nil:
		return shared.NewPATSession(pat.OrgID.String(), pat.Description, shared.SessionActorOrg, strings.Fields(pat.Scopes)), nil
	case pat.ProjectID != nil:
		return shared.NewPATSession(pat.ProjectID.String(), pat.Description, shared.SessionActorProject, strings.Fields(pat.Scopes)), nil
	case pat.AssetID != nil:
		return shared.NewPATSession(pat.AssetID.String(), pat.Description, shared.SessionActorAsset, strings.Fields(pat.Scopes)), nil
	default:
		return nil, fmt.Errorf("invalid token owner type")
	}
}

func (p *PatService) getPubKeyAndUserIDUsingFingerprint(ctx context.Context, fingerprint string) (ecdsa.PublicKey, models.PAT, error) {
	if fingerprint == "" {
		return ecdsa.PublicKey{}, models.PAT{}, fmt.Errorf("no fingerprint provided")
	}
	pat, err := p.patRepository.GetByFingerprint(ctx, nil, fingerprint)
	if err != nil {
		return ecdsa.PublicKey{}, models.PAT{}, fmt.Errorf("could not get public key using fingerprint: %v", err)
	}
	if pat.IsExpired() {
		return ecdsa.PublicKey{}, models.PAT{}, fmt.Errorf("PAT has expired")
	}
	if pat.PubKey == nil {
		return ecdsa.PublicKey{}, models.PAT{}, fmt.Errorf("PAT has no public key")
	}
	pubKey := *pat.PubKey

	pubKeyECDSA, err := HexPubKeyToECDSA(pubKey)
	if err != nil {
		return ecdsa.PublicKey{}, models.PAT{}, fmt.Errorf("could not convert hex pub key to ECDSA: %v", err)
	}

	return pubKeyECDSA, pat, nil
}

// nosemgrep: service-method-missing-ctx -- req.Context() carries the context; adding a separate ctx param would be redundant
func (p *PatService) VerifyAdminRequest(req *http.Request) (bool, error) {
	if !p.adminKeyLoaded {
		return false, fmt.Errorf("cannot verify admin request: no public key was loaded on startup")
	}

	if err := verifySignedRequest(p.adminPubKey, req); err != nil {
		return false, err
	}
	return true, nil
}

func validateRequest(pubKey ecdsa.PublicKey, req *http.Request) error {
	return verifySignedRequest(pubKey, req)
}

// legacySignedFields is what scanners before v1.19 sign. They cannot bind a signature
// to a path, so a captured one can be replayed against any endpoint within the created window.
// TODO: drop the legacy fallback with v1.20
func legacySignedFields() httpsign.Fields {
	return httpsign.Headers("@method", "content-digest")
}

func verifySignature(pubKey ecdsa.PublicKey, fields httpsign.Fields, req *http.Request) error {
	verifier, err := httpsign.NewP256Verifier(pubKey, verifyConfig(), fields)
	if err != nil {
		return fmt.Errorf("could not create verifier: %v", err)
	}
	return httpsign.VerifyRequest("sig77", *verifier, req)
}

// verifySignedRequest verifies the HTTP message signature and then validates that the
// Content-Digest header actually matches the request body
func verifySignedRequest(pubKey ecdsa.PublicKey, req *http.Request) error {
	if err := verifySignature(pubKey, signedFields(), req); err != nil {
		if verifyUnslashed(pubKey, req) != nil {
			if verifySignature(pubKey, legacySignedFields(), req) != nil {
				return fmt.Errorf("could not verify request: %v", err)
			}
			slog.Warn("accepted legacy request signature without @path and @query, client needs to be updated", "path", req.URL.Path, "userAgent", req.UserAgent())
		}
	}

	digest := req.Header.Values("Content-Digest")
	if len(digest) == 0 {
		return fmt.Errorf("missing Content-Digest header")
	}

	if err := httpsign.ValidateContentDigestHeader(digest, &req.Body, []string{httpsign.DigestSha256}); err != nil {
		return fmt.Errorf("content digest does not match request body: %v", err)
	}
	return nil
}

// the addTrailingSlash pre-middleware appends "/" to the path before we get here,
// so a client that signed the path without it would never verify otherwise.
// Both paths are routed identically, so accepting either does not widen what a signature authorizes.
func verifyUnslashed(pubKey ecdsa.PublicKey, req *http.Request) error {
	if !strings.HasSuffix(req.URL.Path, "/") || req.URL.Path == "/" {
		return fmt.Errorf("path has no trailing slash to strip")
	}
	unslashed := req.Clone(req.Context())
	unslashed.URL.Path = strings.TrimSuffix(unslashed.URL.Path, "/")
	unslashed.URL.RawPath = strings.TrimSuffix(unslashed.URL.RawPath, "/")
	return verifySignature(pubKey, signedFields(), unslashed)
}

func (p *PatService) VerifyRequestSignature(ctx context.Context, req *http.Request) (shared.AuthSession, error) {
	fingerprint := req.Header.Get("X-Fingerprint")
	if fingerprint == "" {
		// check if it's an admin request
		isAdmin, err := p.VerifyAdminRequest(req)
		if err != nil {
			return nil, fmt.Errorf("could not verify admin request: %v", err)
		}
		if isAdmin {
			// add all scopes
			return shared.NewSession("admin", shared.SessionActorUser, dtos.AllowedScopes, true), nil
		}
		return nil, fmt.Errorf("no fingerprint provided")
	}
	pubKey, pat, err := p.getPubKeyAndUserIDUsingFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("could not get public key using fingerprint: %v", err)
	}

	if err := validateRequest(pubKey, req); err != nil {
		return nil, fmt.Errorf("could not validate request: %v", err)
	}

	if err := p.patRepository.MarkAsLastUsedNowByID(ctx, nil, pat.ID); err != nil { //nolint:errcheck
		slog.Warn("could not mark pat as last used", "err", err)
	}

	return patToSession(pat)
}

func (p *PatService) RevokeByPrivateKey(ctx context.Context, privKey string) error {
	pubKey, _, err := HexTokenToECDSA(privKey)
	if err != nil {
		return fmt.Errorf("could not convert hex token to ECDSA: %v", err)
	}

	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return fmt.Errorf("could not get public key bytes: %v", err)
	}

	pubKeyString := hex.EncodeToString(pubKeyBytes[1:]) // skip the 0x04 prefix for uncompressed keys

	fingerprint, err := pubKeyToFingerprint(pubKeyString)
	if err != nil {
		return err
	}

	return p.patRepository.DeleteByFingerprint(ctx, nil, fingerprint)
}

func (p *PatService) CheckForValidTokenByFingerprint(ctx context.Context, fingerprint string) (models.PAT, bool) {
	pat, err := p.patRepository.GetByFingerprint(ctx, nil, fingerprint)
	if err != nil {
		return models.PAT{}, false
	}
	if pat.IsExpired() {
		return models.PAT{}, false
	}
	return pat, true
}
