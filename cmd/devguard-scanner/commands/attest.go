// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	cosignattach "github.com/sigstore/cosign/v2/cmd/cosign/cli/attach"
	cosignattest "github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/spf13/cobra"
)

const inTotoPayloadType = "application/vnd.in-toto+json"

func attachAttestation(ctx context.Context, regOpts cosignoptions.RegistryOptions, keyPath, predicatePath, predicateType, imageName string) error {
	return (&cosignattest.AttestCommand{
		KeyOpts: cosignoptions.KeyOpts{
			KeyRef:   keyPath,
			PassFunc: func(_ bool) ([]byte, error) { return []byte{}, nil },
		},
		RegistryOptions: regOpts,
		PredicatePath:   predicatePath,
		PredicateType:   predicateType,
		TlogUpload:      false,
		RekorEntryType:  "dsse",
	}).Exec(ctx, imageName)
}

// preSignedEnvelope returns the DSSE envelope if the content is already signed - either a DSSE envelope or a
// sigstore bundle containing one. It returns nil for plain predicates, which still need to be signed.
func preSignedEnvelope(content []byte, predicateType string) ([]byte, error) {
	var document struct {
		MediaType    string          `json:"mediaType"`
		DsseEnvelope json.RawMessage `json:"dsseEnvelope"`
		PayloadType  *string         `json:"payloadType"`
		Payload      *string         `json:"payload"`
		Signatures   json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		// not a json object - a predicate
		return nil, nil
	}

	envelopeJSON := content
	switch {
	case strings.HasPrefix(document.MediaType, "application/vnd.dev.sigstore.bundle"):
		if len(document.DsseEnvelope) == 0 {
			return nil, fmt.Errorf("sigstore bundle does not contain a dsse envelope")
		}
		envelopeJSON = document.DsseEnvelope
	case document.PayloadType != nil && document.Payload != nil && document.Signatures != nil:
	default:
		return nil, nil
	}

	var envelope dsse.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("invalid dsse envelope: %w", err)
	}
	if envelope.PayloadType != inTotoPayloadType {
		return nil, fmt.Errorf("dsse envelope has payload type %q, expected %q", envelope.PayloadType, inTotoPayloadType)
	}
	if len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("dsse envelope is not signed")
	}

	payload, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("could not decode dsse payload: %w", err)
	}
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("dsse payload is not an in-toto statement: %w", err)
	}
	if statement.PredicateType != predicateType {
		return nil, fmt.Errorf("signed statement has predicate type %q, but --predicateType is %q", statement.PredicateType, predicateType)
	}

	return json.Marshal(envelope)
}

func writeTempEnvelope(content []byte) (string, error) {
	tmp, err := os.CreateTemp("", "devguard-envelope-*.json")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := tmp.Write(content); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func attestCmd(cmd *cobra.Command, args []string) error {
	err := scanner.MaybeLoginIntoOciRegistry(cmd.Context())
	if err != nil {
		return err
	}

	predicate := args[0]

	// if predicate is "-", read from stdin into a temp file
	if predicate == "-" {
		tmp, err := os.CreateTemp("", "devguard-predicate-*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, os.Stdin); err != nil {
			tmp.Close()
			return fmt.Errorf("failed to read predicate from stdin: %w", err)
		}
		tmp.Close()
		predicate = tmp.Name()
	}

	content, err := os.ReadFile(predicate)
	if err != nil {
		slog.Error("could not read file", "file", predicate, "err", err)
		return err
	}

	// the image is optional - without it the attestation is only uploaded
	imageName := ""
	if len(args) == 2 {
		imageName = args[1]
	}

	envelope, err := preSignedEnvelope(content, config.RuntimeAttestationConfig.PredicateType)
	if err != nil {
		return err
	}
	if envelope != nil {
		// already signed attestations (e.g. build provenance signed by devguard) are attached and uploaded as they are
		slog.Info("input is already signed (dsse envelope), attaching it as-is without signing it again", "file", args[0])
		return attestPreSigned(cmd.Context(), envelope, imageName)
	}
	return signAndAttest(cmd.Context(), predicate, imageName)
}

// signAndAttest signs the predicate with the key derived from the token, attaches it to the image and uploads it.
func signAndAttest(ctx context.Context, predicatePath, imageName string) error {
	if imageName != "" {
		slog.Info("attesting image", "predicate", predicatePath, "predicateType", config.RuntimeAttestationConfig.PredicateType, "image", imageName)

		// transform the hex private key to an ecdsa private key
		keyPath, _, err := scanner.TokenToKey(config.RuntimeBaseConfig.Token)
		if err != nil {
			slog.Error("could not convert hex token to ecdsa private key", "err", err)
			return err
		}
		defer os.RemoveAll(path.Dir(keyPath))

		if err := attachAttestation(ctx, registryOptions(), keyPath, predicatePath, config.RuntimeAttestationConfig.PredicateType, imageName); err != nil {
			slog.Error("could not attest predicate", "predicate", predicatePath, "image", imageName, "err", err)
			return err
		}
	}
	return uploadAttestation(ctx, predicatePath)
}

// attestPreSigned attaches the signed DSSE envelope to the image and uploads it - without signing it again.
func attestPreSigned(ctx context.Context, envelope []byte, imageName string) error {
	envelopePath, err := writeTempEnvelope(envelope)
	if err != nil {
		return err
	}
	defer os.Remove(envelopePath)

	if imageName != "" {
		slog.Info("attaching signed attestation to image", "predicateType", config.RuntimeAttestationConfig.PredicateType, "image", imageName)
		if err := cosignattach.AttestationCmd(ctx, registryOptions(), []string{envelopePath}, imageName); err != nil {
			slog.Error("could not attach signed attestation", "image", imageName, "err", err)
			return err
		}
	}
	return uploadAttestation(ctx, envelopePath)
}

func uploadAttestation(ctx context.Context, attestationPath string) error {
	if config.RuntimeBaseConfig.Offline {
		slog.Info("not uploading attestation to backend due to --offline flag", "attestation", attestationPath)
		return nil
	}
	return scanner.UploadAttestation(ctx, attestationPath)
}

func registryOptions() cosignoptions.RegistryOptions {
	return cosignoptions.RegistryOptions{
		AuthConfig: authn.AuthConfig{
			Username: config.RuntimeBaseConfig.Username,
			Password: config.RuntimeBaseConfig.Password,
		},
	}
}

func NewAttestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attest <predicate> [container-image]",
		Short:             "Create and upload an attestation for an image or artifact",
		DisableAutoGenTag: true,
		Long: `Attach a signed metadata document (called a "predicate") to a container image or artifact.

Attestations answer the question "how was this artifact produced?" by associating it with
verifiable metadata. The --predicateType flag identifies what kind of metadata it is. Downstream
consumers (e.g. 'devguard-scanner attestations --policy ...') match attestations by predicate type,
so the value must match exactly what the consumer expects.

Official predicate types are maintained at:
  https://github.com/in-toto/attestation/tree/main/spec/predicates

Common ones used with DevGuard:
  https://cyclonedx.org/bom                         CycloneDX SBOM
  https://cyclonedx.org/vex                         CycloneDX VEX (vulnerability exceptions)
  https://slsa.dev/provenance/v1                    SLSA build provenance
  https://in-toto.io/attestation/release/v0.1       DevGuard release attestation

The first argument is a path to a local predicate JSON file. Pass "-" to read from stdin.
Optionally provide a container image reference as the second argument to also attach the
attestation directly to the image in the OCI registry using cosign.

Already signed input - a DSSE envelope or a sigstore bundle containing one, like the SLSA
provenance signed by 'devguard-scanner provenance sign' - is attached and uploaded as-is,
without signing it again. Its statement must have the predicate type given by --predicateType.`,
		Example: `  # Attest a container image with a VEX predicate
  devguard-scanner attest vex.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Attest with SLSA provenance
  devguard-scanner attest provenance.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Attach SLSA provenance signed by DevGuard as-is
  devguard-scanner provenance sign build.provenance.json > build.provenance.dsse.json
  devguard-scanner attest build.provenance.dsse.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Pipe curl output directly into attest (no shell needed)
  devguard-scanner curl https://api.example.com/sbom.json --token=... | devguard-scanner attest - ghcr.io/org/image:tag --predicateType https://cyclonedx.org/bom

  # Upload attestation without attaching to an image
  devguard-scanner attest predicate.json --predicateType https://example.com/custom/v1

  # Attach an attestation to an image without uploading it to DevGuard (e.g. a multi-arch manifest)
  devguard-scanner attest sbom.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/bom --offline`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestCmd(cmd, args)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			config.ParseAttestationConfig()
		},
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner attest — Create and upload an attestation",
			"description":     "Attach a signed predicate to a container image or artifact and upload it to DevGuard with devguard-scanner attest for verifiable build provenance.",
			"keyword_primary": "devguard-scanner attest",
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("predicateType", "a", "", "The predicate type (URI) for the attestation, e.g. https://slsa.dev/provenance/v1 or https://cyclonedx.org/vex/1.0")
	cmd.MarkFlagRequired("predicateType") //nolint:errcheck
	cmd.MarkFlagRequired("token")         //nolint:errcheck

	// allow username, password and registry to be provided as well as flags
	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (if required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (if required)")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to (optional)")
	cmd.Flags().String("artifactName", "", "The name of the artifact which was scanned. If empty, a name will be generated from the asset name.")
	cmd.Flags().BoolP("offline", "o", false, "If set, do not upload the attestation to the backend. Useful for testing, debugging, or attesting artifacts that have no corresponding DevGuard asset (e.g. a multi-arch manifest).")
	return cmd
}
