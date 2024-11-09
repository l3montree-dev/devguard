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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
)

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

type messageDigest struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type messageSignature struct {
	MessageDigest messageDigest `json:"messageDigest"`
	Signature     string        `json:"signature"`
}

type VerificationMaterial struct {
	PublicKey struct {
		Hint string `json:"hint"`
	} `json:"publicKey"`
}

type bundle struct {
	MessageSignature     messageSignature `json:"messageSignature"`
	MediaType            string           `json:"mediaType"`
	VerificationMaterial `json:"verificationMaterial"`
}

func verifyCommand(cmd *cobra.Command, args []string) {
	// get the public key from the flag
	hexPubKey, err := cmd.Flags().GetString("publicKey")
	if err != nil {
		slog.Error("could not get public key", "err", err)
		os.Exit(1)
	}

	// create a public key from the hex string
	pubKey := pat.HexPubKeyToECDSA(hexPubKey)

	// open the file - provided in the args
	bundlePath, err := cmd.Flags().GetString("bundle")
	if err != nil {
		slog.Error("could not get bundle path", "err", err)
		os.Exit(1)
	}

	// open the bundle
	bundleFile, err := os.ReadFile(bundlePath)
	if err != nil {
		slog.Error("could not open bundle", "err", err)
		os.Exit(1)
	}

	// parse the bundleFile into a map
	var bundle bundle
	err = json.Unmarshal(bundleFile, &bundle)
	if err != nil {
		slog.Error("could not unmarshal bundle", "err", err)
		os.Exit(1)
	}

	// open the artifact (provided in the args)
	artifactPath := args[0]
	artifact, err := os.Open(artifactPath)
	if err != nil {
		slog.Error("could not open artifact", "err", err)
		os.Exit(1)
	}

	verifier, err := signature.LoadVerifier(&pubKey, crypto.SHA256)
	if err != nil {
		slog.Error("could not load verifier", "err", err)
		os.Exit(1)
	}

	sig, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		slog.Error("could not decode signature", "err", err)
		os.Exit(1)
	}

	err = verifier.VerifySignature(bytes.NewBuffer(sig), artifact)
	if err != nil {
		slog.Error("could not verify signature", "err", err)
		os.Exit(1)
	}

	slog.Info("signature verified")
}

func NewVerifyCommand() *cobra.Command {
	verifyCommand := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature",
		Long:  `Verify a signature of an artifact.`,
		// Args:  cobra.ExactArgs(0),
		Run: verifyCommand,
	}

	verifyCommand.Flags().String("publicKey", "", "The public key to verify the signature with")
	verifyCommand.MarkFlagRequired("publicKey") // nolint: errcheck

	verifyCommand.Flags().String("bundle", "", "The cosign bundle to verify (contains the signature)")
	verifyCommand.MarkFlagRequired("bundle") // nolint: errcheck

	return verifyCommand
}
