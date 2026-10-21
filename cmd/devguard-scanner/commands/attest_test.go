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
	"encoding/base64"
	"strings"
	"testing"
)

// signedEnvelope returns a DSSE envelope with an in-toto statement of the given predicate type.
func signedEnvelope(predicateType string) string {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + predicateType + `","subject":[],"predicate":{}}`))
	return `{"payloadType":"application/vnd.in-toto+json","payload":"` + payload + `","signatures":[{"keyid":"","sig":"c2ln"}]}`
}

func TestPreSignedEnvelope(t *testing.T) {
	const slsa = "https://slsa.dev/provenance/v1"

	t.Run("plain predicates are not pre-signed", func(t *testing.T) {
		for _, predicate := range []string{`{"bomFormat":"CycloneDX"}`, `[1,2,3]`} {
			envelope, err := preSignedEnvelope([]byte(predicate), slsa)
			if err != nil || envelope != nil {
				t.Errorf("expected %s to be treated as predicate, got envelope %s and err %v", predicate, envelope, err)
			}
		}
	})

	t.Run("dsse envelopes are pre-signed", func(t *testing.T) {
		envelope, err := preSignedEnvelope([]byte(signedEnvelope(slsa)), slsa)
		if err != nil || envelope == nil {
			t.Fatalf("expected the envelope to be detected, got err %v", err)
		}
	})

	t.Run("the dsse envelope is taken from sigstore bundles", func(t *testing.T) {
		bundle := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"dsseEnvelope":` + signedEnvelope(slsa) + `}`
		envelope, err := preSignedEnvelope([]byte(bundle), slsa)
		if err != nil || envelope == nil {
			t.Fatalf("expected the envelope to be extracted, got err %v", err)
		}
		if strings.Contains(string(envelope), "mediaType") {
			t.Errorf("expected only the envelope, got the bundle: %s", envelope)
		}
	})

	t.Run("unsigned envelopes are rejected", func(t *testing.T) {
		unsigned := strings.Replace(signedEnvelope(slsa), `[{"keyid":"","sig":"c2ln"}]`, `[]`, 1)
		if _, err := preSignedEnvelope([]byte(unsigned), slsa); err == nil {
			t.Error("expected an error for an unsigned envelope")
		}
	})

	t.Run("envelopes with another predicate type are rejected", func(t *testing.T) {
		if _, err := preSignedEnvelope([]byte(signedEnvelope("https://cyclonedx.org/vex")), slsa); err == nil {
			t.Error("expected an error for a mismatching predicate type")
		}
	})
}
