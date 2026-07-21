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
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/yaronf/httpsign"
)

type PatService struct {
	patRepository     shared.PersonalAccessTokenRepository
	assetRepository   shared.AssetRepository
	projectRepository shared.ProjectRepository
	adminPubKey       ecdsa.PublicKey
	adminKeyLoaded    bool
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

func (p *PatService) IsAllowedInOrg(ctx shared.Context, session shared.AuthSession, obj shared.Object, act shared.Action) (bool, error) {
	sessionOwnerType := session.GetOwnerType()
	ownerID := session.GetOwnerID()
	requestGoesToOrg := shared.GetOrg(ctx)
	switch sessionOwnerType {
	case dtos.OwnerUser:
		// get the rbac
		rbac := shared.GetRBAC(ctx)

		// continue with RBAC system
		return rbac.IsAllowed(ctx.Request().Context(), session, obj, act)
	case dtos.OwnerOrg:
		// owner id is an org id
		// an org access token should have access to EVERYTHING inside an organization
		if act == shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToOrg.ID.String(), nil

	case dtos.OwnerProject:
		if act != shared.ActionRead {
			return false, nil
		}
		// we allow org read request for an project token, if the project is part of the organization
		parsedOwnerID, err := uuid.Parse(ownerID)
		if err != nil {
			return false, err
		}
		project, err := p.projectRepository.Read(ctx.Request().Context(), nil, parsedOwnerID)
		if err != nil {
			return false, err
		}
		if requestGoesToOrg.ID != project.OrganizationID {
			return false, nil
		}
		// we already did the database query for the project
		// lets store it in the context to avoid doing the query again
		shared.SetProject(ctx, project)
		return true, nil

	case dtos.OwnerAsset:
		if act != shared.ActionRead {
			return false, nil
		}
		// we allow org read request for an asset token, if the asset is part of the organization
		parsedOwnerID, err := uuid.Parse(ownerID)
		// make sure we preload the project - maybe hy adding a new function "ReadWithProject"
		asset, err := p.assetRepository.ReadWithProject(ctx.Request().Context(), nil, parsedOwnerID)
		if err != nil {
			return false, err
		}
		if requestGoesToOrg.ID != asset.Project.OrganizationID {
			return false, nil
		}

		// set project and asset to context
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, asset.Project)

		return true, nil
	}
	return false, nil
}

func (p *PatService) IsAllowedInProject(ctx shared.Context, session shared.AuthSession, obj shared.Object, act shared.Action) (bool, error) {
	sessionOwnerType := session.GetOwnerType()
	ownerID := session.GetOwnerID()
	requestGoesToOrg := shared.GetOrg(ctx)
	requestGoesToProject := shared.GetProject(ctx)
	switch sessionOwnerType {
	case dtos.OwnerUser:
		// get the rbac
		rbac := shared.GetRBAC(ctx)

		// continue with RBAC system
		return rbac.IsAllowed(ctx.Request().Context(), session, obj, act)

	case dtos.OwnerOrg:
		// owner id is an org id
		// an org access token should have access to EVERYTHING inside an organization
		if act == shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToOrg.ID.String(), nil
	case dtos.OwnerProject:
		if act == shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToProject.ID.String(), nil
	case dtos.OwnerAsset:
		if act != shared.ActionRead {
			return false, nil
		}
		// we allow org read request for an asset token, if the asset is part of the organization
		parsedOwnerID, err := uuid.Parse(ownerID)
		connectedOrgID, err := p.assetRepository.Read(ctx.Request().Context(), nil, parsedOwnerID)
		if err != nil {
			return false, err
		}
		if requestGoesToOrg.ID != connectedOrgID.ProjectID {
			return false, nil
		}

		return true, nil
	}
	return false, nil
}

func (p *PatService) IsAllowedInAsset(ctx shared.Context, session shared.AuthSession, obj shared.Object, act shared.Action) (bool, error) {
	sessionOwnerType := session.GetOwnerType()
	ownerID := session.GetOwnerID()
	requestGoesToOrg := shared.GetOrg(ctx)
	requestGoesToProject := shared.GetProject(ctx)
	requestGoesToAsset := shared.GetAsset(ctx)
	switch sessionOwnerType {
	case dtos.OwnerUser:
		// get the rbac
		rbac := shared.GetRBAC(ctx)

		// continue with RBAC system
		return rbac.IsAllowed(ctx.Request().Context(), session, obj, act)

	case dtos.OwnerOrg:
		// owner id is an org id
		// an org access token should have access to EVERYTHING inside an organization
		if act == shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToOrg.ID.String(), nil

	case dtos.OwnerProject:
		if act != shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToProject.ID.String(), nil

	case dtos.OwnerAsset:
		if act != shared.ActionUpdate {
			return false, nil
		}
		return ownerID == requestGoesToAsset.ID.String(), nil
	}
	return false, nil
}

func ownerToFields(o dtos.TokenOwner) (userID *uuid.UUID, orgID *uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) {
	switch o.Type {
	case dtos.OwnerUser:
		return &o.ID, nil, nil, nil
	case dtos.OwnerOrg:
		return nil, &o.ID, nil, nil
	case dtos.OwnerProject:
		return nil, nil, &o.ID, nil
	case dtos.OwnerAsset:
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

func hexPrivKeyToPubKey(hexPrivKey string) (ecdsa.PublicKey, error) {
	privKeyD := new(big.Int)

	_, err := privKeyD.SetString(hexPrivKey, 16)
	if !err {
		return ecdsa.PublicKey{}, fmt.Errorf("could not parse hexPrivKey")
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: privKeyD,
	}
	privKey.X, privKey.Y = privKey.ScalarBaseMult(privKey.D.Bytes())

	pubKey := &privKey.PublicKey
	return *pubKey, nil
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
	x := new(big.Int).SetBytes(decoded[:32])
	y := new(big.Int).SetBytes(decoded[32:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("public key point is not on P256 curve")
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

func hexPrivKeyToPrivKeyECDSA(hexPrivKey string) ecdsa.PrivateKey {
	privKeyD := new(big.Int)
	privKeyD.SetString(hexPrivKey, 16)

	privKeyECDSA := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: privKeyD,
	}
	privKeyECDSA.X, privKeyECDSA.Y = privKeyECDSA.ScalarBaseMult(privKeyECDSA.D.Bytes())

	return *privKeyECDSA
}

func HexPubKeyToECDSA(hexPubKey string) (ecdsa.PublicKey, error) {
	// A P-256 public key is two 32-byte coordinates = 64 hex bytes each = 128 chars total.
	if len(hexPubKey) != 128 {
		return ecdsa.PublicKey{}, fmt.Errorf("invalid public key length: expected 128 hex chars, got %d", len(hexPubKey))
	}

	x, okX := new(big.Int).SetString(hexPubKey[:64], 16)
	y, okY := new(big.Int).SetString(hexPubKey[64:], 16)
	if !okX || !okY {
		return ecdsa.PublicKey{}, fmt.Errorf("invalid public key: could not parse hex coordinates")
	}

	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return ecdsa.PublicKey{}, fmt.Errorf("invalid public key: point is not on P-256 curve")
	}

	return ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func HexTokenToECDSA(hexToken string) (ecdsa.PrivateKey, ecdsa.PublicKey, error) {
	pubKey, err := hexPrivKeyToPubKey(hexToken)
	if err != nil {
		return ecdsa.PrivateKey{}, ecdsa.PublicKey{}, fmt.Errorf("could not convert hex token to public key: %v", err)
	}

	privKeyECDSA := hexPrivKeyToPrivKeyECDSA(hexToken)

	return privKeyECDSA, pubKey, nil
}

// use a helper function for consistency across the code
func signedFields() httpsign.Fields {
	return httpsign.Headers("@method", "content-digest")
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

	pubKeyString := hex.EncodeToString(pubKey.X.Bytes()) + hex.EncodeToString(pubKey.Y.Bytes())

	fingerprint, err := pubKeyToFingerprint(pubKeyString)
	if err != nil {
		return err
	}

	signer, _ := httpsign.NewP256Signer(privKey, nil, signedFields())

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

func (p *PatService) VerifyAPIToken(ctx context.Context, token string) (string, string, error) {
	if token == "" {
		return "", "", fmt.Errorf("invalid token format")
	}

	pat, err := p.patRepository.GetByBearerTokenHash(ctx, nil, utils.HashString(token))
	if err != nil {
		return "", "", fmt.Errorf("could not verify bearer token: %w", err)
	}
	if pat.IsExpired() {
		return "", "", fmt.Errorf("bearer token has expired")
	}

	if err := p.patRepository.MarkAsLastUsedNowByID(ctx, nil, pat.ID); err != nil {
		slog.Warn("could not mark pat as last used", "err", err)
	}
	return pat.UserID.String(), pat.Scopes, nil
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

	pubKeyECDSA := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	pubKeyECDSA.X, _ = new(big.Int).SetString(pubKey[:len(pubKey)/2], 16)
	pubKeyECDSA.Y, _ = new(big.Int).SetString(pubKey[len(pubKey)/2:], 16)

	return pubKeyECDSA, pat, nil
}

// nosemgrep: service-method-missing-ctx -- req.Context() carries the context; adding a separate ctx param would be redundant
func (p *PatService) VerifyAdminRequest(req *http.Request) (bool, error) {
	if !p.adminKeyLoaded {
		slog.Error("no admin public key could be found")
		return false, fmt.Errorf("cannot verify admin request: no public key was loaded on startup")
	}

	verifier, err := httpsign.NewP256Verifier(p.adminPubKey, nil, signedFields())
	if err != nil {
		return false, fmt.Errorf("could not build P256Verifier: %w", err)
	}

	if err := verifySignedRequest(verifier, req); err != nil {
		return false, err
	}
	return true, nil
}

func validateRequest(pubKey ecdsa.PublicKey, req *http.Request) error {
	verifier, err := httpsign.NewP256Verifier(pubKey, nil, signedFields())
	if err != nil {
		return fmt.Errorf("could not create verifier: %v", err)
	}

	return verifySignedRequest(verifier, req)
}

// verifySignedRequest verifies the HTTP message signature and then validates that the
// Content-Digest header actually matches the request body
func verifySignedRequest(verifier *httpsign.Verifier, req *http.Request) error {
	if err := httpsign.VerifyRequest("sig77", *verifier, req); err != nil {
		return fmt.Errorf("could not verify request: %v", err)
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
			return accesscontrol.NewSession("admin", dtos.AllowedScopes, true), nil
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

	scopesArray := strings.Fields(pat.Scopes)
	return accesscontrol.NewSession(pat.UserID.String(), scopesArray, false), nil
}

func (p *PatService) RevokeByPrivateKey(ctx context.Context, privKey string) error {
	pubKey, _, err := HexTokenToECDSA(privKey)
	if err != nil {
		return fmt.Errorf("could not convert hex token to ECDSA: %v", err)
	}

	pubKeyString := hex.EncodeToString(pubKey.X.Bytes()) + hex.EncodeToString(pubKey.Y.Bytes())

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
