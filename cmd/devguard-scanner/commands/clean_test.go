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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// pushDummyImage pushes a random image to the given tag in the test registry.
func pushDummyImage(t *testing.T, tag name.Tag, remoteOpts []remote.Option) {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := remote.Write(tag, img, remoteOpts...); err != nil {
		t.Fatalf("remote.Write %s: %v", tag, err)
	}
}

// tagExists returns true if the given tag resolves to a manifest in the registry.
func tagExists(tag name.Tag, remoteOpts []remote.Option) bool {
	_, err := remote.Head(tag, remoteOpts...)
	return err == nil
}

func setupRegistry(t *testing.T) (host string, regOpts cosignoptions.RegistryOptions, remoteOpts []remote.Option) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	host = strings.TrimPrefix(srv.URL, "http://")
	regOpts = cosignoptions.RegistryOptions{AllowInsecure: true}
	remoteOpts = regOpts.GetRegistryClientOpts(context.Background())
	return
}

func pushBaseImage(t *testing.T, imageRef string, remoteOpts []remote.Option) name.Reference {
	t.Helper()
	img, err := random.Image(512, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	ref, err := name.ParseReference(imageRef, name.Insecure)
	if err != nil {
		t.Fatalf("name.ParseReference: %v", err)
	}
	if err := remote.Write(ref, img, remoteOpts...); err != nil {
		t.Fatalf("remote.Write base image: %v", err)
	}
	return ref
}

func TestCleanImageCleanTypeAllRemovesAllTags(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	ref := pushBaseImage(t, imageRef, remoteOpts)

	attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("AttestationTag: %v", err)
	}
	sigTag, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("SignatureTag: %v", err)
	}

	pushDummyImage(t, attTag, remoteOpts)
	pushDummyImage(t, sigTag, remoteOpts)

	// pre-condition: both tags exist
	if !tagExists(attTag, remoteOpts) {
		t.Fatal("attestation tag should exist before clean")
	}
	if !tagExists(sigTag, remoteOpts) {
		t.Fatal("signature tag should exist before clean")
	}

	if err := cleanImage(context.Background(), regOpts, cosignoptions.CleanTypeAll, imageRef); err != nil {
		t.Fatalf("cleanImage: %v", err)
	}

	if tagExists(attTag, remoteOpts) {
		t.Error("attestation tag should have been deleted")
	}
	if tagExists(sigTag, remoteOpts) {
		t.Error("signature tag should have been deleted")
	}
}

func TestCleanImageCleanTypeAttestationLeavesSignatureTag(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	ref := pushBaseImage(t, imageRef, remoteOpts)

	attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("AttestationTag: %v", err)
	}
	sigTag, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("SignatureTag: %v", err)
	}

	pushDummyImage(t, attTag, remoteOpts)
	pushDummyImage(t, sigTag, remoteOpts)

	if err := cleanImage(context.Background(), regOpts, cosignoptions.CleanTypeAttestation, imageRef); err != nil {
		t.Fatalf("cleanImage: %v", err)
	}

	if tagExists(attTag, remoteOpts) {
		t.Error("attestation tag should have been deleted")
	}
	if !tagExists(sigTag, remoteOpts) {
		t.Error("signature tag should still exist after attestation-only clean")
	}
}

func TestCleanImageCleanTypeSignatureLeavesAttestationTag(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	ref := pushBaseImage(t, imageRef, remoteOpts)

	attTag, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("AttestationTag: %v", err)
	}
	sigTag, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("SignatureTag: %v", err)
	}

	pushDummyImage(t, attTag, remoteOpts)
	pushDummyImage(t, sigTag, remoteOpts)

	if err := cleanImage(context.Background(), regOpts, cosignoptions.CleanTypeSignature, imageRef); err != nil {
		t.Fatalf("cleanImage: %v", err)
	}

	if !tagExists(attTag, remoteOpts) {
		t.Error("attestation tag should still exist after signature-only clean")
	}
	if tagExists(sigTag, remoteOpts) {
		t.Error("signature tag should have been deleted")
	}
}

func TestCleanImageNoTagsDoesNotError(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	pushBaseImage(t, imageRef, remoteOpts)

	// no attestation/signature tags present — clean should still succeed
	if err := cleanImage(context.Background(), regOpts, cosignoptions.CleanTypeAll, imageRef); err != nil {
		t.Fatalf("cleanImage on image with no sig/att tags failed: %v", err)
	}
}
