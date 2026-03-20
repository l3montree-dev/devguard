// Copyright (C) 2025 l3montree GmbH
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
package scanner

import (
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path"

	cosignpkg "github.com/sigstore/cosign/v2/pkg/cosign"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/services"
)

func TokenToKey(token string) (string, string, error) {
	// transform the hex private key to an ecdsa private key
	privKey, _, err := services.HexTokenToECDSA(token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		os.Exit(1)
	}

	// encode the private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		slog.Error("could not marshal private key", "err", err)
		return "", "", err
	}

	tempDir := path.Join(os.TempDir(), uuid.New().String())
	err = os.Mkdir(tempDir, 0700)
	if err != nil {
		slog.Error("could not create temp dir", "err", err)
		return "", "", err
	}

	ecKeyPath := path.Join(tempDir, "ecdsa.pem")
	file, err := os.OpenFile(ecKeyPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		slog.Error("could not create file", "err", err)
		return "", "", err
	}
	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	file.Close()
	if err != nil {
		slog.Error("could not encode private key to PEM", "err", err)
		return "", "", err
	}

	// Use the cosign Go library to convert EC key → cosign-encrypted key format
	// (replaces: cosign import-key-pair --output-key-prefix cosign --key ecdsa.pem)
	keysBytes, err := cosignpkg.ImportKeyPair(ecKeyPath, func(_ bool) ([]byte, error) {
		return []byte{}, nil // empty password
	})
	if err != nil {
		slog.Error("could not import key pair", "err", err)
		return "", "", err
	}
	os.Remove(ecKeyPath)

	cosignKeyPath := path.Join(tempDir, "cosign.key")
	if err = os.WriteFile(cosignKeyPath, keysBytes.PrivateBytes, 0600); err != nil {
		slog.Error("could not write cosign key", "err", err)
		return "", "", err
	}

	cosignPubPath := path.Join(tempDir, "cosign.pub")
	if err = os.WriteFile(cosignPubPath, keysBytes.PublicBytes, 0644); err != nil {
		slog.Error("could not write cosign public key", "err", err)
		return "", "", err
	}

	return cosignKeyPath, cosignPubPath, nil
}
