package pat

import (
	"bufio"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
)

func TestGetPubKeyUsingFingerprint(t *testing.T) {
	t.Run("test getPubKey Using Fingerprint", func(t *testing.T) {

		var pat = models.PAT{
			PubKey: "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5",
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything).Return(pat, nil)
		patService := NewPatService(patMock)

		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"
		pubKey_X := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f296"
		pubKey_Y := "1892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		fingerprint := "fffdeb60-7eb8-45a5-aaaa-35e051c2eeb6"

		pubKeyCheck, _, _, err := patService.getPubKeyAndUserIdUsingFingerprint(fingerprint)
		if err != nil {
			t.Fatal(err)
		}

		if pubKey_X != hex.EncodeToString(pubKeyCheck.X.Bytes()) {
			t.Fatalf("expected %s, got %s", pubKey_X, hex.EncodeToString(pubKeyCheck.X.Bytes()))
		}

		if pubKey_Y != hex.EncodeToString(pubKeyCheck.Y.Bytes()) {
			t.Fatalf("expected %s, got %s", pubKey_Y, hex.EncodeToString(pubKeyCheck.Y.Bytes()))
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

func TestSignRequest(t *testing.T) {
	t.Run("test signing and verifying", func(t *testing.T) {

		var pat = models.PAT{
			PubKey: "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5",
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything).Return(pat, nil)
		patMock.On("MarkAsLastUsedNow", mock.Anything).Return(nil)

		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := SignRequest(privKey, req)
		if err != nil {
			t.Fatal("error", err)
		}

		//privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		_, _, err = patService.VerifyRequestSignature(req)
		if err != nil {
			t.Fatal("error", err)
		}

	})
	t.Run("test signing and verifying fails, after having tampered with the request", func(t *testing.T) {
		var pat = models.PAT{
			PubKey: "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5",
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything).Return(pat, nil)
		patMock.On("MarkAsLastUsedNow", mock.Anything).Return(nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := SignRequest(privKey, req)
		if err != nil {
			t.Fatal("error", err)
		}
		req.Header.Set("Content-Digest", "POST")

		_, _, err = patService.VerifyRequestSignature(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

	})

	t.Run("test signing and verifying fails, after having tampered with the method header", func(t *testing.T) {
		var pat = models.PAT{
			PubKey: "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5",
		}

		patMock := new(mocks.PersonalAccessTokenRepository)
		patMock.On("GetByFingerprint", mock.Anything).Return(pat, nil)
		patService := NewPatService(patMock)

		privKey := "1a73970f31816d996ab514c4ffea04b6dee0eadc107267d0c911fd817a7b5167"
		//pubKey := "b7c43ec092437bee964bb0b4babb017035db0fec3dae273254d1a0eed2c1f2961892101c1f186ff599d16574a9d5386660b52ad88224c8a8c010e1e2572d9df5"

		reader := bufio.NewReader(strings.NewReader(`{"user": "test"}`))
		req := httptest.NewRequest("GET", "/", reader)

		err := SignRequest(privKey, req)
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

		_, _, err = patService.VerifyRequestSignature(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

	})
}
