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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

type AttestationFileLine struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"` // base64 encoded AttestationPayload
}

// DiscoverAttestations fetches and decodes attestations for a container image
// without relying on the cosign CLI binary.
func DiscoverAttestations(image string, predicateType string) ([]map[string]any, error) {
	ctx := context.Background()

	// Parse the image reference
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse image reference")
	}

	attestations := []map[string]any{}

	// Construct the attestation reference by appending .att to the tag
	// Cosign stores attestations in a separate manifest with this suffix
	attRef, err := ociremote.AttestationTag(ref)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct attestation reference")
	}

	// Fetch attestations using the constructed reference
	sigs, err := ociremote.Signatures(attRef,
		ociremote.WithRemoteOptions(
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithContext(ctx),
		),
	)
	if err != nil {
		// If error contains "not found" or similar, return empty list
		if strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "MANIFEST_UNKNOWN") ||
			strings.Contains(err.Error(), "NAME_UNKNOWN") {
			return attestations, nil
		}
		return nil, errors.Wrap(err, "failed to fetch attestations")
	}

	// Iterate through all attestation signatures
	attList, err := sigs.Get()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get attestation list")
	}

	for _, att := range attList {
		// Get the payload - this is the DSSE envelope or Simple Signing payload
		payload, err := att.Payload()
		if err != nil {
			continue // Skip invalid attestations
		}

		// First try to parse as DSSE envelope (newer format)
		var envelope struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		}

		// Check if this looks like JSON by checking the first byte
		if len(payload) > 0 && payload[0] == '{' {
			if err := json.Unmarshal(payload, &envelope); err == nil && envelope.Payload != "" {
				// Successfully parsed as DSSE envelope
				// Decode the base64 payload
				decodedPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
				if err != nil {
					continue // Skip invalid base64
				}

				// Parse the attestation
				var attestation map[string]any
				if err := json.Unmarshal(decodedPayload, &attestation); err != nil {
					continue // Skip invalid JSON
				}

				// Check if it has predicateType (characteristic of in-toto attestations)
				predType, hasPredType := attestation["predicateType"].(string)
				if !hasPredType {
					continue // Not an attestation
				}

				// Filter by predicate type if specified
				if predicateType != "" && predType != predicateType {
					continue
				}

				attestations = append(attestations, attestation)
				continue
			}
		}

		// If not DSSE, try Simple Signing format (payload is the attestation directly)
		// The payload might be the attestation itself
		var attestation map[string]any
		if err := json.Unmarshal(payload, &attestation); err != nil {
			continue // Skip if not valid JSON
		}

		// Check if it has predicateType (characteristic of in-toto attestations)
		predType, hasPredType := attestation["predicateType"].(string)
		if !hasPredType {
			continue // Not an attestation
		}

		// Filter by predicate type if specified
		if predicateType != "" && predType != predicateType {
			continue
		}

		attestations = append(attestations, attestation)
	}

	if len(attestations) == 0 && predicateType != "" {
		return nil, fmt.Errorf("no attestations found with predicate type: %s", predicateType)
	}

	return attestations, nil
}
