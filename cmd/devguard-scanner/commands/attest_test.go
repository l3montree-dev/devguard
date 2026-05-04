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

package commands

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cosignpkg "github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"net/http/httptest"

	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

// writeKeyFile generates a fresh cosign key pair and writes the private key to
// a temp file, returning its path. The key is encrypted with an empty password.
func writeKeyFile(t *testing.T) string {
	t.Helper()
	keys, err := cosignpkg.GenerateKeyPair(func(_ bool) ([]byte, error) {
		return []byte{}, nil
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cosign.key")
	if err := os.WriteFile(keyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return keyPath
}

// writePredicateFile writes predicate JSON to a temp file and returns its path.
func writePredicateFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "predicate.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write predicate file: %v", err)
	}
	return p
}

func TestAttachAttestationCreatesAttestationTag(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	regOpts := cosignoptions.RegistryOptions{AllowInsecure: true}
	remoteOpts := regOpts.GetRegistryClientOpts(context.Background())

	// Push a base image
	img, err := random.Image(512, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	ref, err := name.ParseReference(host+"/test/image:latest", name.Insecure)
	if err != nil {
		t.Fatalf("name.ParseReference: %v", err)
	}
	if err := remote.Write(ref, img, remoteOpts...); err != nil {
		t.Fatalf("remote.Write: %v", err)
	}

	keyPath := writeKeyFile(t)
	predicatePath := writePredicateFile(t, `{"component":"test","version":"1.0"}`)

	if err := attachAttestation(
		context.Background(),
		regOpts,
		keyPath,
		predicatePath,
		"https://cyclonedx.org/vex",
		host+"/test/image:latest",
	); err != nil {
		t.Fatalf("attachAttestation: %v", err)
	}

	attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("AttestationTag: %v", err)
	}
	if !tagExists(attTag, remoteOpts) {
		t.Error("attestation tag should exist after attachAttestation")
	}
}

func TestAttachAttestationDifferentPredicateTypes(t *testing.T) {
	predicateTypes := []string{
		"https://cyclonedx.org/vex",
		"https://slsa.dev/provenance/v1",
		"https://spdx.dev/Document",
	}

	for _, pt := range predicateTypes {
		t.Run(pt, func(t *testing.T) {
			srv := httptest.NewServer(registry.New())
			t.Cleanup(srv.Close)
			host := strings.TrimPrefix(srv.URL, "http://")

			regOpts := cosignoptions.RegistryOptions{AllowInsecure: true}
			remoteOpts := regOpts.GetRegistryClientOpts(context.Background())

			img, err := random.Image(512, 1)
			if err != nil {
				t.Fatalf("random.Image: %v", err)
			}
			ref, err := name.ParseReference(host+"/test/image:latest", name.Insecure)
			if err != nil {
				t.Fatalf("name.ParseReference: %v", err)
			}
			if err := remote.Write(ref, img, remoteOpts...); err != nil {
				t.Fatalf("remote.Write: %v", err)
			}

			keyPath := writeKeyFile(t)
			predicatePath := writePredicateFile(t, `{"test":true}`)

			if err := attachAttestation(
				context.Background(), regOpts, keyPath, predicatePath, pt, host+"/test/image:latest",
			); err != nil {
				t.Fatalf("attachAttestation(%s): %v", pt, err)
			}

			attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
			if err != nil {
				t.Fatalf("AttestationTag: %v", err)
			}
			if !tagExists(attTag, remoteOpts) {
				t.Errorf("attestation tag should exist for predicate type %s", pt)
			}
		})
	}
}

func TestAttachAttestationIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	regOpts := cosignoptions.RegistryOptions{AllowInsecure: true}
	remoteOpts := regOpts.GetRegistryClientOpts(context.Background())

	img, err := random.Image(512, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	ref, err := name.ParseReference(host+"/test/image:latest", name.Insecure)
	if err != nil {
		t.Fatalf("name.ParseReference: %v", err)
	}
	if err := remote.Write(ref, img, remoteOpts...); err != nil {
		t.Fatalf("remote.Write: %v", err)
	}

	keyPath := writeKeyFile(t)
	predicatePath := writePredicateFile(t, `{"component":"test"}`)
	imageRef := host + "/test/image:latest"

	// Attest twice with the same predicate — should not error
	for i := range 2 {
		if err := attachAttestation(context.Background(), regOpts, keyPath, predicatePath, "https://cyclonedx.org/vex", imageRef); err != nil {
			t.Fatalf("attachAttestation call %d: %v", i+1, err)
		}
	}

	attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("AttestationTag: %v", err)
	}
	if !tagExists(attTag, remoteOpts) {
		t.Error("attestation tag should exist after double attest")
	}
}
