// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package commands

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type keypair struct {
	privateKey    *ecdsa.PrivateKey
	options       *sign.EphemeralKeypairOptions
	hashAlgorithm protocommon.HashAlgorithm
}

var _ sign.Keypair = &keypair{}

func newKeypair(privateKey *ecdsa.PrivateKey, opts *sign.EphemeralKeypairOptions) (*keypair, error) {

	if opts == nil {
		opts = &sign.EphemeralKeypairOptions{}
	}

	if opts.Hint == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	}

	return &keypair{
		privateKey:    privateKey,
		options:       opts,
		hashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
	}, nil
}

func (k *keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.hashAlgorithm
}

func (k *keypair) GetHint() []byte {
	return k.options.Hint
}

func (k *keypair) GetKeyAlgorithm() string {
	return "ecdsa"
}

func (k *keypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(k.privateKey.Public())
	if err != nil {
		return "", err
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPem), nil
}

func getHashFunc(hashAlgorithm protocommon.HashAlgorithm) (crypto.Hash, error) {
	switch hashAlgorithm {
	case protocommon.HashAlgorithm_SHA2_256:
		return crypto.Hash(crypto.SHA256), nil
	case protocommon.HashAlgorithm_SHA2_384:
		return crypto.Hash(crypto.SHA384), nil
	case protocommon.HashAlgorithm_SHA2_512:
		return crypto.Hash(crypto.SHA512), nil
	default:
		var hash crypto.Hash
		return hash, errors.New("Unsupported hash algorithm")
	}
}

func (k *keypair) SignData(data []byte) ([]byte, []byte, error) {
	hashFunc, err := getHashFunc(k.hashAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	hasher := hashFunc.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := k.privateKey.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, nil, err
	}

	return signature, digest, nil
}

func signCmd(cmd *cobra.Command, args []string) {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		slog.Error("could not get token", "err", err)
		os.Exit(1)
	}

	inToto, err := cmd.Flags().GetBool("in-toto")
	if err != nil {
		slog.Error("could not get in-toto flag", "err", err)
		os.Exit(1)
	}

	// transform the hex private key to an ecdsa private key
	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		os.Exit(1)
	}

	keypair, err := newKeypair(&privKey, nil)
	if err != nil {
		slog.Error("could not create keypair", "err", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		slog.Error("could not read file", "err", err)
		os.Exit(1)
	}

	var content sign.Content

	if inToto {
		content = &sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	} else {
		content = &sign.PlainData{
			Data: data,
		}
	}

	if err != nil {
		slog.Error("could not read file", "err", err)
		os.Exit(1)
	}

	opts := sign.BundleOptions{}

	/*rekorOpts := &sign.RekorOptions{
		BaseURL: "https://rekor.sigstage.dev",
		Timeout: time.Duration(90 * time.Second),
		Retries: 1,
	}

	opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
	*/

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		slog.Error("could not create bundle", "err", err)
		os.Exit(1)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		slog.Error("could not marshal bundle", "err", err)
		os.Exit(1)
	}

	// write the bundle to a file
	err = os.WriteFile("bundle.json", bundleJSON, 0600)
	if err != nil {
		slog.Error("could not write bundle to file", "err", err)
		os.Exit(1)
	}
}

func NewSignCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <file>",
		Short: "Sign a file",
		Long:  `Sign a file`,
		Args:  cobra.ExactArgs(1),
		Run:   signCmd,
	}
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.Flags().Bool("in-toto", false, "The file to sign is an in-toto document")
	cmd.MarkPersistentFlagRequired("token") // nolint:errcheck

	return cmd
}
