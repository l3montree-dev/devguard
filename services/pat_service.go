package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
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

var _ shared.Verifier = (*PatService)(nil) // Ensure PatService implements shared.PatService interface

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

func (p *PatService) ToModel(ctx context.Context, request dtos.PatCreateRequest, userID string) models.PAT {
	//token := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
	fingerprint, err := pubKeyToFingerprint(request.PubKey)
	if err != nil {
		slog.Error("could not convert public key to fingerprint", "err", err)
		return models.PAT{}
	}

	//check if the scopes are valid
	ok := utils.ContainsAll(dtos.AllowedScopes, strings.Fields(request.Scopes))
	if !ok {
		slog.Error("invalid scopes", "scopes", request.Scopes)
		return models.PAT{}
	}

	pat := models.PAT{
		UserID:      uuid.MustParse(userID),
		Description: request.Description,
		Scopes:      request.Scopes,
		PubKey:      request.PubKey,
		Fingerprint: fingerprint,
	}

	//pat.Token = pat.HashToken(token)
	return pat // return the unhashed token. This is the token that will be sent to the user
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

func SignRequest(hexPrivKey string, req *http.Request) error {
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

func (p *PatService) getPubKeyAndUserIDUsingFingerprint(ctx context.Context, fingerprint string) (ecdsa.PublicKey, uuid.UUID, string, error) {
	pat, err := p.patRepository.GetByFingerprint(ctx, nil, fingerprint)
	if err != nil {
		return ecdsa.PublicKey{}, uuid.New(), "", fmt.Errorf("could not get public key using fingerprint: %v", err)
	}
	pubKey := pat.PubKey

	pubKeyECDSA :=
		ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int),
			Y:     new(big.Int),
		}

	pubKeyECDSA.X, _ = new(big.Int).SetString(pubKey[:len(pubKey)/2], 16)
	pubKeyECDSA.Y, _ = new(big.Int).SetString(pubKey[len(pubKey)/2:], 16)

	return pubKeyECDSA, pat.UserID, pat.Scopes, nil
}

func (p *PatService) markAsLastUsedNow(ctx context.Context, fingerprint string) error {
	return p.patRepository.MarkAsLastUsedNow(ctx, nil, fingerprint)
}

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
	pubKey, userID, scopes, err := p.getPubKeyAndUserIDUsingFingerprint(ctx, fingerprint)

	if err != nil {
		return nil, fmt.Errorf("could not get public key using fingerprint: %v", err)
	}

	if err := validateRequest(pubKey, req); err != nil {
		return nil, fmt.Errorf("could not validate request: %v", err)
	}

	p.markAsLastUsedNow(ctx, fingerprint) //nolint:errcheck// we don't care if this fails

	scopesArray := strings.Fields(scopes)
	return accesscontrol.NewSession(userID.String(), scopesArray, false), nil
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
