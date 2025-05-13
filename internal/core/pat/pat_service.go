package pat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/yaronf/httpsign"
)

type PatService struct {
	patRepository core.PersonalAccessTokenRepository
}

func NewPatService(repository core.PersonalAccessTokenRepository) *PatService {
	return &PatService{
		patRepository: repository,
	}
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
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

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
	privKeyECDSA.PublicKey.X, privKeyECDSA.PublicKey.Y = privKeyECDSA.PublicKey.Curve.ScalarBaseMult(privKeyECDSA.D.Bytes())

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

func (p *PatService) getPubKeyAndUserIdUsingFingerprint(fingerprint string) (ecdsa.PublicKey, uuid.UUID, string, error) {
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

func (p *PatService) VerifyRequestSignature(req *http.Request) (string, string, error) {
	fingerprint := req.Header.Get("X-Fingerprint")
	pubKey, userId, scopes, err := p.getPubKeyAndUserIdUsingFingerprint(fingerprint)

	if err != nil {
		return "", "", fmt.Errorf("could not get public key using fingerprint: %v", err)
	}

	//config := httpsign.NewVerifyConfig().SetKeyID("my-shared-secret").SetVerifyCreated(false) // for testing only
	verifier, _ := httpsign.NewP256Verifier(pubKey, nil,
		httpsign.Headers("@method", "content-digest"))

	err = httpsign.VerifyRequest("sig77", *verifier, req)
	if err != nil {
		return "", "", fmt.Errorf("could not verify request: %v", err)
	}

	p.markAsLastUsedNow(fingerprint) //nolint:errcheck// we don't care if this fails

	return userId.String(), scopes, nil
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
