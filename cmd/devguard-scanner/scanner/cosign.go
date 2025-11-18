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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"os/exec"
	"path"

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
	// create a new temporary file to store the private key - the file needs to have minimum permissions
	tempDir := path.Join(os.TempDir(), uuid.New().String())
	err = os.Mkdir(
		tempDir,
		0700,
	)
	if err != nil {
		slog.Error("could not create temp dir", "err", err)
		return "", "", err
	}

	file, err := os.OpenFile(path.Join(tempDir, "ecdsa.pem"), os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		slog.Error("could not create file", "err", err)
		return "", "", err
	}

	// encode the private key to PEM
	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		slog.Error("could not encode private key to PEM", "err", err)
		return "", "", err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	// import the cosign key
	importCmd := exec.Command("cosign", "import-key-pair", "--output-key-prefix", "cosign", "--key", "ecdsa.pem")
	importCmd.Dir = tempDir
	importCmd.Stdout = &out
	importCmd.Stderr = &errOut
	importCmd.Env = []string{"COSIGN_PASSWORD="}

	err = importCmd.Run()
	if err != nil {
		slog.Error("could not import key", "err", err, "out", out.String(), "errOut", errOut.String())
		return "", "", err
	}

	return path.Join(tempDir, "cosign.key"), path.Join(tempDir, "cosign.pub"), nil
}
