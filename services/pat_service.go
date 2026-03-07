package services

import (
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

func (p *PatService) ToModel(request dtos.PatCreateRequest, userID string) models.PAT {
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

	//config := httpsign.NewSignConfig().SignCreated(false).SetNonce("BADCAB").SetKeyID("my-shared-secret") // SignCreated should be "true" to protect against replay attacks
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

func (p *PatService) getPubKeyAndUserIDUsingFingerprint(fingerprint string) (ecdsa.PublicKey, uuid.UUID, string, error) {
	pat, err := p.patRepository.GetByFingerprint(fingerprint)
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

func (p *PatService) markAsLastUsedNow(fingerprint string) error {
	return p.patRepository.MarkAsLastUsedNow(fingerprint)
}

func (p *PatService) verifyAdminRequest(req *http.Request) (bool, error) {
	verifier, _ := httpsign.NewP256Verifier(p.adminPubKey, nil,
		httpsign.Headers("@method", "content-digest"))

	err := httpsign.VerifyRequest("sig77", *verifier, req)
	if err != nil {
		return false, fmt.Errorf("could not verify request: %v", err)
	}
	return true, nil
}

func validateRequest(pubKey ecdsa.PublicKey, req *http.Request) error {
	verifier, err := httpsign.NewP256Verifier(pubKey, nil,
		httpsign.Headers("@method", "content-digest"))

	if err != nil {
		return fmt.Errorf("could not create verifier: %v", err)
	}

	err = httpsign.VerifyRequest("sig77", *verifier, req)
	if err != nil {
		return fmt.Errorf("could not verify request: %v", err)
	}
	return nil
}

func (p *PatService) VerifyRequestSignature(req *http.Request) (shared.AuthSession, error) {
	fingerprint := req.Header.Get("X-Fingerprint")
	if fingerprint == "" {
		// check if it's an admin request
		isAdmin, err := p.verifyAdminRequest(req)
		if err != nil {
			return nil, fmt.Errorf("could not verify admin request: %v", err)
		}
		if isAdmin {
			// add all scopes
			return accesscontrol.NewSession("admin", dtos.AllowedScopes, true), nil
		}
		return nil, fmt.Errorf("no fingerprint provided")
	}
	pubKey, userID, scopes, err := p.getPubKeyAndUserIDUsingFingerprint(fingerprint)

	if err != nil {
		return nil, fmt.Errorf("could not get public key using fingerprint: %v", err)
	}

	if err := validateRequest(pubKey, req); err != nil {
		return nil, fmt.Errorf("could not validate request: %v", err)
	}

	p.markAsLastUsedNow(fingerprint) //nolint:errcheck// we don't care if this fails

	scopesArray := strings.Fields(scopes)
	return accesscontrol.NewSession(userID.String(), scopesArray, false), nil
}

func (p *PatService) RevokeByPrivateKey(privKey string) error {
	pubKey, _, err := HexTokenToECDSA(privKey)
	if err != nil {
		return fmt.Errorf("could not convert hex token to ECDSA: %v", err)
	}

	pubKeyString := hex.EncodeToString(pubKey.X.Bytes()) + hex.EncodeToString(pubKey.Y.Bytes())

	fingerprint, err := pubKeyToFingerprint(pubKeyString)
	if err != nil {
		return err
	}

	return p.patRepository.DeleteByFingerprint(fingerprint)
}
