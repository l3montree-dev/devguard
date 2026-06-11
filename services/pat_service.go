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
	patRepository shared.PersonalAccessTokenRepository
}

var _ shared.Verifier = (*PatService)(nil) // Ensure PatService implements shared.PatService interface

func NewPatService(repository shared.PersonalAccessTokenRepository) *PatService {
	return &PatService{patRepository: repository}
}

func (p *PatService) ToModel(_ context.Context, request dtos.PatCreateRequest, userID string) (models.PAT, string, error) {
	if !utils.ContainsAll(dtos.AllowedScopes, strings.Fields(request.Scopes)) {
		return models.PAT{}, "", fmt.Errorf("invalid scopes: %s", request.Scopes)
	}

	expiry := utils.Ptr(time.Now().Add(time.Second * time.Duration(request.ExpireAfterSeconds)))

	if request.IsSymmetric() {
		cleartext, hash, err := generateBearerToken()
		if err != nil {
			return models.PAT{}, "", fmt.Errorf("could not generate bearer token: %w", err)
		}
		return models.PAT{
			UserID:          uuid.MustParse(userID),
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
		UserID:      uuid.MustParse(userID),
		Description: request.Description,
		Scopes:      request.Scopes,
		PubKey:      request.PubKey,
		Fingerprint: &fingerprint,
		ExpiryDate:  expiry,
	}, "", nil
}

// generateBearerToken creates a random dvg_-prefixed token and returns the cleartext and its hash.
func generateBearerToken() (cleartext, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	cleartext = "dvg_" + hex.EncodeToString(raw)
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

func HexPubKeyToECDSA(hexPubKey string) ecdsa.PublicKey {
	pubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	pubKey.X, _ = new(big.Int).SetString(hexPubKey[:len(hexPubKey)/2], 16)
	pubKey.Y, _ = new(big.Int).SetString(hexPubKey[len(hexPubKey)/2:], 16)

	return pubKey
}

func HexTokenToECDSA(hexToken string) (ecdsa.PrivateKey, ecdsa.PublicKey, error) {
	pubKey, err := hexPrivKeyToPubKey(hexToken)
	if err != nil {
		return ecdsa.PrivateKey{}, ecdsa.PublicKey{}, fmt.Errorf("could not convert hex token to public key: %v", err)
	}

	privKeyECDSA := hexPrivKeyToPrivKeyECDSA(hexToken)

	return privKeyECDSA, pubKey, nil
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

	fields := httpsign.Headers("@method", "content-digest")

	signer, _ := httpsign.NewP256Signer(privKey, nil, fields)

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

func (p *PatService) VerifyRequestSignature(ctx context.Context, req *http.Request) (string, string, error) {
	fingerprint := req.Header.Get("X-Fingerprint")
	if fingerprint == "" {
		return "", "", fmt.Errorf("no fingerprint provided")
	}
	pubKey, pat, err := p.getPubKeyAndUserIDUsingFingerprint(ctx, fingerprint)
	if err != nil {
		return "", "", fmt.Errorf("could not get public key using fingerprint: %v", err)
	}

	verifier, _ := httpsign.NewP256Verifier(pubKey, nil,
		httpsign.Headers("@method", "content-digest"))

	err = httpsign.VerifyRequest("sig77", *verifier, req)
	if err != nil {
		return "", "", fmt.Errorf("could not verify request: %v", err)
	}

	if err := p.patRepository.MarkAsLastUsedNowByID(ctx, nil, pat.ID); err != nil { //nolint:errcheck
		slog.Warn("could not mark pat as last used", "err", err)
	}

	return pat.UserID.String(), pat.Scopes, nil
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
