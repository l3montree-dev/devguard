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

package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func verifySignature(ctx context.Context, pubKeyFile string, sigFile string, blobFile string) error {
	// Load the public key
	pubKeyData, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return fmt.Errorf("could not read public key: %w", err)
	}

	// PEM-Block dekodieren
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return fmt.Errorf("could not decode pem block")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse public key: %w", err)
	}

	// ECDSA-key generation
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to parse public key")
	}

	// Load the signature file
	sigFileData, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("could not read signature file: %w", err)
	}

	// decode base64 signature
	base64Sig := string(sigFileData)
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return fmt.Errorf("could not decode base64 signature: %w", err)
	}

	// load the block using a reader
	file, err := os.Open(blobFile)
	if err != nil {
		return fmt.Errorf("could not read blob file: %w", err)
	}

	// setup verifier
	verifier, err := signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("could not load verifier: %w", err)
	}

	// Verify the signature
	err = verifier.VerifySignature(bytes.NewReader(sig), file, options.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}

	return nil
}

type tableIntegrityInformation struct {
	TableName  string `json:"table_name"`
	Checksum   []byte `json:"checksum"`
	TotalCount int    `json:"total_count"`
}

type integrityInformation struct {
	TableIntegrity  []tableIntegrityInformation `json:"table_integrity"`
	ImportTimestamp time.Time                   `json:"import_timestamp"`
}

// returns a string slice with failing tables
// if nil, then all tables are valid
func validateIntegrityInformation(workingDir string, groundTruth integrityInformation, localIntegrityInformation []tableIntegrityInformation) ([]string, bool) {
	failingTables := make([]string, 0)
	for _, tableIntegrity := range localIntegrityInformation {
		found := false
		for _, tableGroundTruth := range groundTruth.TableIntegrity {
			if tableGroundTruth.TableName == tableIntegrity.TableName {
				found = true
				if !tableIntegrity.isEqual(tableGroundTruth) {
					slog.Error("invalid checksum when importing", "table", tableIntegrity.TableName, "expectedCount", tableGroundTruth.TotalCount, "actualCount", tableIntegrity.TotalCount, "expectedChecksum", fmt.Sprintf("%x", tableGroundTruth.Checksum), "actualChecksum", fmt.Sprintf("%x", tableIntegrity.Checksum))
					failingTables = append(failingTables, tableIntegrity.TableName)
				} else {
					break
				}
			}
		}
		if !found {
			slog.Error("unexpected table found when importing", "table", tableIntegrity.TableName, "count", tableIntegrity.TotalCount, "checksum", fmt.Sprintf("%x", tableIntegrity.Checksum))
			failingTables = append(failingTables, tableIntegrity.TableName)
		}
	}
	if len(failingTables) > 0 {
		return failingTables, false
	}

	return nil, true
}

func calculateTotalIntegrityInformation(ctx context.Context, tx pgx.Tx) ([]tableIntegrityInformation, error) {
	const query = `
		WITH
		cves_integrity AS (
			SELECT 'cves' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id::text, '\0') || '|' ||
					coalesce(description, '\0') || '|' ||
					coalesce(cvss::text, '\0') || '|' ||
					coalesce(vector, '\0')
				) AS row_hash FROM cves
			) sub
		),
		cve_relationships_integrity AS (
			SELECT 'cve_relationships' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY source_cve, target_cve, relationship_type)) AS checksum
			FROM (
				SELECT source_cve, target_cve, relationship_type,
				       md5(source_cve || '|' || target_cve || '|' || relationship_type) AS row_hash
				FROM cve_relationships
			) sub
		),
		cve_affected_component_integrity AS (
			SELECT 'cve_affected_component' AS table_name, count(*) AS row_count,
			       md5(
			           count(*)::text || '|' ||
			           coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 0))::text, '0') || '|' ||
			           coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 1))::text, '0')
			       ) AS checksum
			FROM cve_affected_component
		),
		affected_components_integrity AS (
			SELECT 'affected_components' AS table_name, count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM affected_components
		),
		exploits_integrity AS (
			SELECT 'exploits' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id, cve_id, source_url, row_hash)) AS checksum
			FROM (
				SELECT id, cve_id, source_url, md5(
					coalesce(id, '\0') || '|' ||
					coalesce(cve_id, '\0') || '|' ||
					coalesce(source_url, '\0')
				) AS row_hash FROM exploits
			) sub
		),
		malicious_packages_integrity AS (
			SELECT 'malicious_packages' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(coalesce(id, '\0') || '|' || coalesce(modified::text, '\0')) AS row_hash
				FROM malicious_packages WHERE id NOT LIKE 'MAL-FAKE-TEST-%'
			) sub
		),
		malicious_affected_components_integrity AS (
			SELECT 'malicious_affected_components' AS table_name, count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM malicious_affected_components WHERE malicious_package_id NOT LIKE 'MAL-FAKE-TEST-%'
		)
		SELECT table_name, row_count, checksum FROM cves_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM cve_relationships_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM cve_affected_component_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM affected_components_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM exploits_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM malicious_packages_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM malicious_affected_components_integrity
	`

	slog.Info("start calculating integrity information")
	start := time.Now()
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("could not calculate integrity information: %w", err)
	}
	defer rows.Close()

	results := make([]tableIntegrityInformation, 0, 7)
	for rows.Next() {
		var r tableIntegrityInformation
		if err := rows.Scan(&r.TableName, &r.TotalCount, &r.Checksum); err != nil {
			return nil, fmt.Errorf("could not scan integrity row: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("could not read integrity rows: %w", err)
	}
	slog.Info("finished calculating integrity information", "took", time.Since(start).Round(time.Millisecond))
	for _, r := range results {
		slog.Info("integrity", "table", r.TableName, "rows", r.TotalCount, "checksum", fmt.Sprintf("%x", r.Checksum))
	}

	return results, nil
}

func (integrity tableIntegrityInformation) isEqual(compareInformation tableIntegrityInformation) bool {
	return integrity.TotalCount == compareInformation.TotalCount && bytes.Equal(integrity.Checksum, compareInformation.Checksum)
}
