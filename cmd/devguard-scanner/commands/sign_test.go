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
	"testing"

	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func TestSignImageCreatesSignatureTag(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	ref := pushBaseImage(t, imageRef, remoteOpts)

	keyPath := writeKeyFile(t)
	ko := cosignoptions.KeyOpts{
		KeyRef:   keyPath,
		PassFunc: func(_ bool) ([]byte, error) { return []byte{}, nil },
	}

	if err := signImage(ko, regOpts, imageRef); err != nil {
		t.Fatalf("signImage: %v", err)
	}

	sigTag, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("SignatureTag: %v", err)
	}
	if !tagExists(sigTag, remoteOpts) {
		t.Error("signature tag should exist after signImage")
	}
}

func TestSignImageIsIdempotent(t *testing.T) {
	host, regOpts, remoteOpts := setupRegistry(t)
	imageRef := host + "/test/image:latest"

	ref := pushBaseImage(t, imageRef, remoteOpts)

	keyPath := writeKeyFile(t)
	ko := cosignoptions.KeyOpts{
		KeyRef:   keyPath,
		PassFunc: func(_ bool) ([]byte, error) { return []byte{}, nil },
	}

	for i := range 2 {
		if err := signImage(ko, regOpts, imageRef); err != nil {
			t.Fatalf("signImage call %d: %v", i+1, err)
		}
	}

	sigTag, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("SignatureTag: %v", err)
	}
	if !tagExists(sigTag, remoteOpts) {
		t.Error("signature tag should exist after double sign")
	}
}
