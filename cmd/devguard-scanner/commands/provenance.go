// Copyright (C) 2026 l3montree GmbH
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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// workloadIdentityTokenEnv is the variable name the GitLab id_tokens keyword should use for the devguard token
const workloadIdentityTokenEnv = "DEVGUARD_ID_TOKEN"

func signProvenanceCmd(cmd *cobra.Command, args []string) error {
	idToken, err := cmd.Flags().GetString("idToken")
	if err != nil {
		return err
	}
	if idToken == "" {
		idToken = os.Getenv(workloadIdentityTokenEnv)
	}

	var statement []byte
	if args[0] == "-" {
		statement, err = io.ReadAll(os.Stdin)
	} else {
		statement, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("could not read provenance: %w", err)
	}

	var signed []byte
	switch {
	case idToken != "":
		signed, err = scanner.SignBuildProvenance(cmd.Context(), statement, idToken)
	case config.RuntimeBaseConfig.Token != "":
		slog.Warn("no workload identity token provided - signing the provenance with the devguard token instead. " +
			"This provenance is only self asserted (SLSA Build L1): nothing verified who built the artifact, and everyone holding the token can sign arbitrary provenance. " +
			"Request a workload identity token with the audience of the devguard api and expose it as " + workloadIdentityTokenEnv + " to let DevGuard sign it (SLSA Build L2+)")
		signed, err = signProvenanceWithToken(cmd.Context(), statement, config.RuntimeBaseConfig.Token)
	default:
		return fmt.Errorf("neither a workload identity token nor a devguard token provided. Use --idToken or %s to let DevGuard sign the provenance, or --token to sign it yourself", workloadIdentityTokenEnv)
	}
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	if err := writeProvenance(output, signed); err != nil {
		return err
	}
	slog.Info("signed build provenance", "output", output)
	return nil
}

// signProvenanceWithToken signs the provenance with the key derived from the devguard token - the key 'devguard-scanner sign'
// and 'attest' use as well. The builder id marks the provenance as self signed, since no build platform verified it.
func signProvenanceWithToken(ctx context.Context, statement []byte, token string) ([]byte, error) {
	var parsed attestationv1.Statement
	if err := protojson.Unmarshal(statement, &parsed); err != nil {
		return nil, fmt.Errorf("could not parse in-toto statement: %w", err)
	}
	if parsed.PredicateType != dtos.SLSAProvenanceV1PredicateType {
		return nil, fmt.Errorf("unsupported predicate type %q, expected %q", parsed.PredicateType, dtos.SLSAProvenanceV1PredicateType)
	}
	predicate, err := protojson.Marshal(parsed.Predicate)
	if err != nil {
		return nil, err
	}
	var provenance provenancev1.Provenance
	if err := protojson.Unmarshal(predicate, &provenance); err != nil {
		return nil, fmt.Errorf("could not parse slsa provenance predicate: %w", err)
	}

	if provenance.RunDetails == nil {
		provenance.RunDetails = &provenancev1.RunDetails{}
	}
	provenance.RunDetails.Builder = &provenancev1.Builder{Id: dtos.SLSASelfSignedBuilderID}

	predicate, err = protojson.Marshal(&provenance)
	if err != nil {
		return nil, err
	}
	parsed.Predicate = &structpb.Struct{}
	if err := protojson.Unmarshal(predicate, parsed.Predicate); err != nil {
		return nil, err
	}
	if err := parsed.Validate(); err != nil {
		return nil, fmt.Errorf("invalid in-toto statement: %w", err)
	}
	payload, err := protojson.Marshal(&parsed)
	if err != nil {
		return nil, err
	}

	privateKey, _, err := services.HexTokenToECDSA(token)
	if err != nil {
		return nil, fmt.Errorf("could not derive the signing key from the devguard token: %w", err)
	}
	envelopeSigner, err := dsse.NewEnvelopeSigner(tokenSigner{key: &privateKey})
	if err != nil {
		return nil, err
	}
	envelope, err := envelopeSigner.SignPayload(ctx, "application/vnd.in-toto+json", payload)
	if err != nil {
		return nil, fmt.Errorf("could not sign provenance: %w", err)
	}
	return json.Marshal(envelope)
}

// tokenSigner signs dsse envelopes with the ecdsa key of a devguard token
type tokenSigner struct {
	key *ecdsa.PrivateKey
}

func (s tokenSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func (s tokenSigner) KeyID() (string, error) {
	return utils.PublicKeyID(&s.key.PublicKey)
}

func writeProvenance(output string, content []byte) error {
	if output == "" || output == "-" {
		_, err := os.Stdout.Write(content)
		return err
	}
	if err := os.WriteFile(output, content, 0644); err != nil {
		return fmt.Errorf("could not write provenance: %w", err)
	}
	return nil
}

func generateProvenanceCmd(cmd *cobra.Command, args []string) error {
	// --image and --path are the image and path of the scanner config, which holds single strings - so both are comma separated
	images := splitCommaSeparated(config.RuntimeBaseConfig.Image)
	paths := splitCommaSeparated(config.RuntimeBaseConfig.Path)
	inputs, err := cmd.Flags().GetStringArray("input")
	if err != nil {
		return err
	}
	startedOn, err := cmd.Flags().GetString("startedOn")
	if err != nil {
		return err
	}
	finishedOn, err := cmd.Flags().GetString("finishedOn")
	if err != nil {
		return err
	}

	statement, err := generateProvenanceStatement(images, paths, inputs, startedOn, finishedOn)
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	return writeProvenance(output, statement)
}

func splitCommaSeparated(list string) []string {
	var values []string
	for value := range strings.SplitSeq(list, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// generateProvenanceStatement builds the unsigned statement DevGuard signs. It only contains what the client knows:
// the built images and files, the inputs of the workflow and the build timestamps. Everything describing the build
// platform is set by DevGuard from the workload identity token when signing.
func generateProvenanceStatement(images []string, files []string, inputs []string, startedOn string, finishedOn string) ([]byte, error) {
	if len(images) == 0 && len(files) == 0 {
		return nil, fmt.Errorf("no subject given. Pass the built images with --image or the built files with --path")
	}

	statement := &attestationv1.Statement{
		Type:          attestationv1.StatementTypeUri,
		PredicateType: dtos.SLSAProvenanceV1PredicateType,
	}
	for _, image := range images {
		subject, err := imageSubject(image)
		if err != nil {
			return nil, err
		}
		statement.Subject = append(statement.Subject, subject)
	}
	for _, file := range files {
		subject, err := fileSubject(file)
		if err != nil {
			return nil, err
		}
		statement.Subject = append(statement.Subject, subject)
	}

	inputValues := make(map[string]any, len(inputs))
	for _, input := range inputs {
		key, value, ok := strings.Cut(input, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid input %q, expected key=value", input)
		}
		if _, exists := inputValues[key]; exists {
			return nil, fmt.Errorf("input %q is set more than once", key)
		}
		inputValues[key] = value
	}
	externalParameters, err := structpb.NewStruct(map[string]any{"inputs": inputValues})
	if err != nil {
		return nil, err
	}

	metadata := &provenancev1.BuildMetadata{}
	if metadata.StartedOn, err = parseProvenanceTimestamp("startedOn", startedOn); err != nil {
		return nil, err
	}
	if metadata.FinishedOn, err = parseProvenanceTimestamp("finishedOn", finishedOn); err != nil {
		return nil, err
	}

	provenance := &provenancev1.Provenance{
		BuildDefinition: &provenancev1.BuildDefinition{
			BuildType:          dtos.SLSACIWorkflowBuildType,
			ExternalParameters: externalParameters,
		},
	}
	if metadata.StartedOn != nil || metadata.FinishedOn != nil {
		provenance.RunDetails = &provenancev1.RunDetails{Metadata: metadata}
	}
	predicate, err := protojson.Marshal(provenance)
	if err != nil {
		return nil, err
	}
	statement.Predicate = &structpb.Struct{}
	if err := protojson.Unmarshal(predicate, statement.Predicate); err != nil {
		return nil, err
	}

	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("invalid in-toto statement: %w", err)
	}
	return protojson.Marshal(statement)
}

func imageSubject(image string) (*attestationv1.ResourceDescriptor, error) {
	name, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || name == "" {
		return nil, fmt.Errorf("invalid image %q, expected an image reference with digest like ghcr.io/org/image@sha256:<digest>", image)
	}
	// the digest itself is checked when the statement is validated
	return &attestationv1.ResourceDescriptor{
		Name:   name,
		Digest: map[string]string{"sha256": digest},
	}, nil
}

// fileSubject hashes a file into a subject named after the file
func fileSubject(path string) (*attestationv1.ResourceDescriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open file %q: %w", path, err)
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return nil, fmt.Errorf("could not hash file %q: %w", path, err)
	}
	return &attestationv1.ResourceDescriptor{
		Name:   filepath.Base(path),
		Digest: map[string]string{"sha256": hex.EncodeToString(hash.Sum(nil))},
	}, nil
}

func parseProvenanceTimestamp(name string, value string) (*timestamppb.Timestamp, error) {
	if value == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q, expected an RFC3339 timestamp: %w", name, value, err)
	}
	return timestamppb.New(t), nil
}

func newGenerateProvenanceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "generate",
		Short:             "Generate unsigned SLSA build provenance for 'devguard-scanner provenance sign'",
		DisableAutoGenTag: true,
		Long: `Generate an in-toto statement with a SLSA v1 provenance predicate for the artifacts a CI run built.

The statement only contains what the CI job knows itself: the built artifacts (subjects), the inputs
the workflow was called with and when the build ran. Everything describing the build platform - the
builder, the workflow, the source commit - is set by DevGuard from the verified workload identity
token when signing with 'devguard-scanner provenance sign'.

Container images are passed with --image as image references with their manifest digest, so the
provenance matches the image it is attached to. Files, e.g. release tarballs, are passed with --path,
hashed and recorded under their file name. Both take a comma separated list.`,
		Example: `  # Generate, sign and attach provenance for an image
  IMAGE_DIGEST=$(crane digest ghcr.io/org/image:1.2.3)
  devguard-scanner provenance generate --image ghcr.io/org/image@$IMAGE_DIGEST \
    --input target=ociImage \
    --startedOn "$BUILD_STARTED_ON" --finishedOn "$BUILD_FINISHED_ON" \
    | devguard-scanner provenance sign - --output provenance.dsse.json
  devguard-scanner attest provenance.dsse.json ghcr.io/org/image@$IMAGE_DIGEST --predicateType https://slsa.dev/provenance/v1

  # Generate provenance for release tarballs
  devguard-scanner provenance generate --path dist/app-linux-amd64.tar.gz,dist/app-darwin-arm64.tar.gz -o provenance.json`,
		Args: cobra.NoArgs,
		RunE: generateProvenanceCmd,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner provenance generate — Generate SLSA build provenance",
			"description":     "Generate unsigned SLSA v1 build provenance for the artifacts of a CI run with devguard-scanner provenance generate.",
			"keyword_primary": "devguard-scanner provenance generate",
		},
	}

	cmd.Flags().String("image", "", "Comma separated built images as references with digest, e.g. ghcr.io/org/image@sha256:<digest>.")
	cmd.Flags().String("path", "", "Comma separated built files to hash, e.g. release tarballs. Recorded under their file name.")
	cmd.Flags().StringArray("input", nil, "An input the workflow was called with as key=value. Recorded at predicate.buildDefinition.externalParameters.inputs. Can be repeated.")
	cmd.Flags().String("startedOn", "", "When the build started, as RFC3339 timestamp.")
	cmd.Flags().String("finishedOn", "", "When the build finished, as RFC3339 timestamp.")
	cmd.Flags().StringP("output", "o", "", "File to write the provenance to. Defaults to stdout.")
	return cmd
}

func newSignProvenanceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sign <provenance>",
		Short:             "Let DevGuard sign SLSA build provenance with the verified identity of the CI job",
		DisableAutoGenTag: true,
		Long: `Send an in-toto statement with a SLSA v1 provenance predicate to DevGuard for signing.

DevGuard verifies the OIDC workload identity token of the CI job with its issuer and writes the
verified identity into the provenance before signing it:

  predicate.runDetails.builder.id                                         the ci config which ran the build
  predicate.buildDefinition.externalParameters.workflow                   the ci config which started the run
  predicate.buildDefinition.internalParameters.devguard.workloadIdentity  the non personal claims of the verified token
  predicate.buildDefinition.resolvedDependencies                          the source commit of the run

Every field describing the build platform is overwritten. Only the subjects,
predicate.buildDefinition.externalParameters.inputs and the startedOn and finishedOn timestamps
are kept as sent.

The token must be issued for the audience of the DevGuard API. In GitLab request it with:

  id_tokens:
    DEVGUARD_ID_TOKEN:
      aud: https://api.devguard.org

Without a workload identity token the provenance is signed locally with the key of the devguard token
(--token) instead, and predicate.runDetails.builder.id is set to ` + dtos.SLSASelfSignedBuilderID + `.
Such provenance is only self asserted (SLSA Build L1): nothing verified who built the artifact.

The result is a DSSE envelope - or a sigstore bundle, if DevGuard uploads to a transparency log.
Pass it to 'devguard-scanner attest' to attach it to an image: already signed input is attached as-is.
The first argument is a path to the provenance JSON file. Pass "-" to read from stdin.`,
		Example: `  # Sign the provenance generated by 'devguard-scanner provenance generate'
  devguard-scanner provenance sign build.provenance.json --output build.provenance.dsse.json

  # Attach the signed provenance to the image without signing it again
  devguard-scanner attest build.provenance.dsse.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Pass the token explicitly and print the signed provenance to stdout
  devguard-scanner provenance sign build.provenance.json --idToken="$MY_ID_TOKEN"`,
		Args: cobra.ExactArgs(1),
		RunE: signProvenanceCmd,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner provenance sign — Sign SLSA build provenance",
			"description":     "Let DevGuard sign SLSA build provenance and embed the verified OIDC workload identity of the CI job with devguard-scanner provenance sign.",
			"keyword_primary": "devguard-scanner provenance sign",
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().String("idToken", "", "The OIDC workload identity token of the CI job. Defaults to the "+workloadIdentityTokenEnv+" environment variable.")
	cmd.Flags().StringP("output", "o", "", "File to write the signed provenance to. Defaults to stdout.")
	return cmd
}

func NewProvenanceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "provenance",
		Short:             "Work with SLSA build provenance",
		DisableAutoGenTag: true,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner provenance — Work with SLSA build provenance",
			"description":     "Sign SLSA build provenance with DevGuard as build control plane using devguard-scanner provenance.",
			"keyword_primary": "devguard-scanner provenance",
		},
	}
	cmd.AddCommand(newGenerateProvenanceCommand(), newSignProvenanceCommand())
	return cmd
}
