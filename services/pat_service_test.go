package services

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/mock"
)

func TestGetPubKeyUsingFingerprint(t *testing.T) {
	t.Run("test getPubKey Using Fingerprint", func(t *testing.T) {

		var pat = models.PAT{
			PubKey:     new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
			ExpiryDate: new(time.Now().Add(time.Hour)),
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patService := NewPatService(patMock)

		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"
		pubKeyX := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f296"
		pubKeyY := "1892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		fingerprint := "fffdeb60-7eb8-45a5-aaaa-35e051c2eeb6"

		pubKeyCheck, pat, err := patService.getPubKeyAndUserIDUsingFingerprint(context.Background(), fingerprint)
		_ = pat
		if err != nil {
			t.Fatal(err)
		}

		if pubKeyX != hex.EncodeToString(pubKeyCheck.X.Bytes()) {
			t.Fatalf("expected %s, got %s", pubKeyX, hex.EncodeToString(pubKeyCheck.X.Bytes()))
		}

		if pubKeyY != hex.EncodeToString(pubKeyCheck.Y.Bytes()) {
			t.Fatalf("expected %s, got %s", pubKeyY, hex.EncodeToString(pubKeyCheck.Y.Bytes()))
		}
	})
}

func TestHexPrivKeyToPubKey(t *testing.T) {
	t.Run("test hexPrivKey to PubKey", func(t *testing.T) {
		priv := "1b210d1412d412bc6d0ce767bd2795353377f568ac3cbad1850797cd36180449"
		pub := "c600494b2ba7254dbfc160ea9f36dbe8b111e7170592f95dba2c2f6ca64caf4aa4e5e6f9b6d82e7b1376fad7c418831689182832f7e25f15fa2a2b6dcb5159eb"
		pubCheck, err := hexPrivKeyToPubKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		p := hex.EncodeToString(pubCheck.X.Bytes()) + hex.EncodeToString(pubCheck.Y.Bytes())
		if pub != p {
			t.Fatalf("expected %s, got %s", pub, pubCheck)
		}
	})
}

func TestPubKeyToFingerprint(t *testing.T) {
	t.Run("test pubKey to fingerprint", func(t *testing.T) {
		pubKey := "c600494b2ba7254dbfc160ea9f36dbe8b111e7170592f95dba2c2f6ca64caf4aa4e5e6f9b6d82e7b1376fad7c418831689182832f7e25f15fa2a2b6dcb5159eb" //nolint

		fingerprint := "a888cdf9fba93f6e2d1b3aa799204eb22f820b2e58519d5573062590895fd184"
		fingerprintCheck, err := pubKeyToFingerprint(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint != fingerprintCheck {
			t.Fatalf("expected %s, got %s", fingerprint, fingerprintCheck)
		}
	})
}

func TestVerifyAPIToken(t *testing.T) {
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	cleartext := "dvg_testtoken"
	tokenHash := utils.HashString(cleartext)

	t.Run("returns userID and scopes for a valid token", func(t *testing.T) {
		patID := uuid.MustParse("00000000-0000-0000-0000-000000000010")
		pat := models.PAT{Scopes: "read write", Fingerprint: new("fp1")}
		pat.UserID = userID
		pat.ID = patID

		patMock := mocks.NewPersonalAccessTokenRepository(t)
		patMock.On("GetByBearerTokenHash", mock.Anything, mock.Anything, tokenHash).Return(pat, nil)
		patMock.On("MarkAsLastUsedNowByID", mock.Anything, mock.Anything, patID).Return(nil)
		patService := NewPatService(patMock)

		gotUserID, gotScopes, err := patService.VerifyAPIToken(context.Background(), cleartext)
		if err != nil {
			t.Fatal(err)
		}
		if gotUserID != userID.String() {
			t.Fatalf("expected userID %s, got %s", userID, gotUserID)
		}
		if gotScopes != "read write" {
			t.Fatalf("expected scopes 'read write', got %s", gotScopes)
		}
		patMock.AssertExpectations(t)
	})

	t.Run("returns error when token not found in repository", func(t *testing.T) {
		patMock := mocks.NewPersonalAccessTokenRepository(t)
		patMock.On("GetByBearerTokenHash", mock.Anything, mock.Anything, mock.Anything).Return(models.PAT{}, errors.New("not found"))
		patService := NewPatService(patMock)

		_, _, err := patService.VerifyAPIToken(context.Background(), cleartext)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("returns error when token is expired", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		pat := models.PAT{Scopes: "scan"}
		pat.UserID = userID
		pat.ExpiryDate = &past

		patMock := mocks.NewPersonalAccessTokenRepository(t)
		patMock.On("GetByBearerTokenHash", mock.Anything, mock.Anything, tokenHash).Return(pat, nil)
		patService := NewPatService(patMock)

		_, _, err := patService.VerifyAPIToken(context.Background(), cleartext)
		if err == nil {
			t.Fatal("expected error for expired token, got nil")
		}
	})

	t.Run("still returns success when MarkAsLastUsedNowByID fails", func(t *testing.T) {
		patID := uuid.MustParse("00000000-0000-0000-0000-000000000011")
		pat := models.PAT{Scopes: "scan", Fingerprint: new("fp2")}
		pat.UserID = userID
		pat.ID = patID

		patMock := mocks.NewPersonalAccessTokenRepository(t)
		patMock.On("GetByBearerTokenHash", mock.Anything, mock.Anything, tokenHash).Return(pat, nil)
		patMock.On("MarkAsLastUsedNowByID", mock.Anything, mock.Anything, patID).Return(errors.New("db error"))
		patService := NewPatService(patMock)

		gotUserID, _, err := patService.VerifyAPIToken(context.Background(), cleartext)
		if err != nil {
			t.Fatalf("expected success despite MarkAsLastUsedNowByID failure, got %v", err)
		}
		if gotUserID != userID.String() {
			t.Fatalf("expected userID %s, got %s", userID, gotUserID)
		}
	})
}

func TestToModel(t *testing.T) {
	userID := "00000000-0000-0000-0000-000000000002"

	t.Run("symmetric: generates bearer token, stores hash, returns cleartext", func(t *testing.T) {
		patService := NewPatService(nil)
		pat, cleartext, err := patService.ToModel(context.Background(), dtos.PatCreateRequest{
			Description: "trivy",
			Scopes:      "scan",
		}, userID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(cleartext, "dvg_") {
			t.Fatalf("expected token to start with dvg_, got %s", cleartext)
		}
		if pat.BearerTokenHash == nil || *pat.BearerTokenHash == "" {
			t.Fatal("expected BearerTokenHash to be set")
		}
		if *pat.BearerTokenHash != utils.HashString(cleartext) {
			t.Fatal("BearerTokenHash does not match hash of cleartext")
		}
		if pat.IsAsymmetricSecret() {
			t.Fatal("expected symmetric PAT")
		}
	})

	t.Run("asymmetric: derives fingerprint, returns empty cleartext", func(t *testing.T) {
		patService := NewPatService(nil)
		pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"
		pat, cleartext, err := patService.ToModel(context.Background(), dtos.PatCreateRequest{
			PubKey: &pubKey,
			Scopes: "scan",
		}, userID)
		if err != nil {
			t.Fatal(err)
		}
		if cleartext != "" {
			t.Fatalf("expected empty cleartext for asymmetric PAT, got %s", cleartext)
		}
		if pat.Fingerprint == nil || *pat.Fingerprint == "" {
			t.Fatal("expected Fingerprint to be set")
		}
		if !pat.IsAsymmetricSecret() {
			t.Fatal("expected asymmetric PAT")
		}
	})

	t.Run("returns error for invalid scopes", func(t *testing.T) {
		patService := NewPatService(nil)
		_, _, err := patService.ToModel(context.Background(), dtos.PatCreateRequest{
			Scopes: "invalid-scope",
		}, userID)
		if err == nil {
			t.Fatal("expected error for invalid scopes")
		}
	})

	t.Run("returns error for invalid public key", func(t *testing.T) {
		patService := NewPatService(nil)
		invalidKey := "not-a-valid-pubkey"
		_, _, err := patService.ToModel(context.Background(), dtos.PatCreateRequest{
			PubKey: &invalidKey,
			Scopes: "scan",
		}, userID)
		if err == nil {
			t.Fatal("expected error for invalid public key")
		}
	})
}

func TestAuthenticateRequestWithToken(t *testing.T) {
	t.Run("test signing and verifying", func(t *testing.T) {

		var pat = models.PAT{
			PubKey:     new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
			ExpiryDate: new(time.Now().Add(time.Hour)),
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patMock.On("MarkAsLastUsedNowByID", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := AuthenticateRequestWithToken(privKey, req)
		if err != nil {
			t.Fatal("error", err)
		}

		//privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		_, err = patService.VerifyRequestSignature(context.Background(), req)
		if err != nil {
			t.Fatal("error", err)
		}

	})
	t.Run("test signing and verifying fails, after having tampered with the request", func(t *testing.T) {
		var pat = models.PAT{
			PubKey:     new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
			ExpiryDate: new(time.Now().Add(time.Hour)),
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patMock.On("MarkAsLastUsedNowByID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := AuthenticateRequestWithToken(privKey, req)
		if err != nil {
			t.Fatal("error", err)
		}
		req.Header.Set("Content-Digest", "POST")

		_, err = patService.VerifyRequestSignature(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

	})

	t.Run("rejects a body swapped after signing (content-digest must be bound to the body)", func(t *testing.T) {
		// An attacker who captures a signed request can keep the Signature + Content-Digest headers
		// verbatim and ship a different body. Here we swap only the body
		// and leave every signed header untouched — verification must still fail.
		var pat = models.PAT{
			PubKey: new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patMock.On("MarkAsLastUsedNow", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"

		reader := bufio.NewReader(strings.NewReader(`{"role": "viewer"}`))
		req := httptest.NewRequest("POST", "/scan/", reader)

		if err := signRequest(privKey, req); err != nil {
			t.Fatal("error", err)
		}

		// Attacker swaps the body, keeping the signed Signature + Content-Digest headers.
		req.Body = io.NopCloser(strings.NewReader(`{"role": "admin"}`))

		if _, err := patService.VerifyRequestSignature(context.Background(), req); err == nil {
			t.Fatal("expected verification to fail when the body no longer matches the signed Content-Digest")
		}
	})

	t.Run("test signing and verifying fails, after having tampered with the method header", func(t *testing.T) {
		var pat = models.PAT{
			PubKey:     new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
			ExpiryDate: new(time.Now().Add(time.Hour)),
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := AuthenticateRequestWithToken(privKey, req)
		if err != nil {
			t.Fatal("error", err)
		}

		// print all headers
		for k, v := range req.Header {
			for _, vv := range v {
				println(k, vv)
			}
		}

		req.Method = "POST"

		_, err = patService.VerifyRequestSignature(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

	})

	t.Run("rejects a valid signature from an expired PAT", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		var pat = models.PAT{
			PubKey:     new("b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"),
			ExpiryDate: &past,
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything, mock.Anything, mock.Anything).Return(pat, nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		if err := AuthenticateRequestWithToken(privKey, req); err != nil {
			t.Fatal("error signing request", err)
		}

		_, err := patService.VerifyRequestSignature(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for expired PAT, got nil")
		}
	})
}

// adminKeyPair is the keypair the instance admin signs requests with. The public
// counterpart is what gets loaded into PatService.adminPubKey on startup.
const adminPrivKey = "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"

func newAdminPatService(t *testing.T) *PatService {
	t.Helper()
	_, adminPubKey, err := HexTokenToECDSA(adminPrivKey)
	if err != nil {
		t.Fatal("could not derive admin public key", err)
	}
	return &PatService{adminPubKey: adminPubKey, adminKeyLoaded: true}
}

func TestVerifyAdminRequest(t *testing.T) {
	t.Run("accepts a request signed with the admin key", func(t *testing.T) {
		patService := newAdminPatService(t)

		req := httptest.NewRequest("POST", "/admin/", strings.NewReader(`{"action": "ban"}`))
		if err := signRequest(adminPrivKey, req); err != nil {
			t.Fatal("could not sign request", err)
		}

		isAdmin, err := patService.VerifyAdminRequest(req)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if !isAdmin {
			t.Fatal("expected request to be verified as admin")
		}
	})

	t.Run("rejects a request signed with a non-admin key", func(t *testing.T) {
		patService := newAdminPatService(t)

		// a valid, well-formed key that simply is not the admin key
		nonAdminPrivKey := "2c73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		req := httptest.NewRequest("POST", "/admin/", strings.NewReader(`{"action": "ban"}`))
		if err := signRequest(nonAdminPrivKey, req); err != nil {
			t.Fatal("could not sign request", err)
		}

		isAdmin, err := patService.VerifyAdminRequest(req)
		if err == nil {
			t.Fatal("expected verification to fail for a non-admin key")
		}
		if isAdmin {
			t.Fatal("a non-admin key must never be granted admin")
		}
	})

	t.Run("rejects when no admin key was loaded on startup", func(t *testing.T) {
		// adminKeyLoaded defaults to false - simulates an instance started without the key
		patService := &PatService{}

		req := httptest.NewRequest("POST", "/admin/", strings.NewReader(`{"action": "ban"}`))
		if err := signRequest(adminPrivKey, req); err != nil {
			t.Fatal("could not sign request", err)
		}

		isAdmin, err := patService.VerifyAdminRequest(req)
		if err == nil {
			t.Fatal("expected an error when no admin key is loaded")
		}
		if isAdmin {
			t.Fatal("must not grant admin when no admin key is loaded")
		}
	})

	t.Run("rejects a tampered admin request", func(t *testing.T) {
		patService := newAdminPatService(t)

		req := httptest.NewRequest("POST", "/admin/", strings.NewReader(`{"action": "read"}`))
		if err := signRequest(adminPrivKey, req); err != nil {
			t.Fatal("could not sign request", err)
		}

		// swap the body after signing - the signed Content-Digest no longer matches
		req.Body = io.NopCloser(strings.NewReader(`{"action": "delete-everything"}`))

		isAdmin, err := patService.VerifyAdminRequest(req)
		if err == nil {
			t.Fatal("expected verification to fail after the body was tampered with")
		}
		if isAdmin {
			t.Fatal("a tampered request must never be granted admin")
		}
	})
}
