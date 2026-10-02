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

package vulndb

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/package-url/packageurl-go"
)

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	repository *repositories.MaliciousPackageRepository
}

type malRows struct {
	pkgs  []models.MaliciousPackage
	comps []models.MaliciousAffectedComponent
}

func NewMaliciousPackageChecker(
	repository *repositories.MaliciousPackageRepository,
) (*MaliciousPackageChecker, error) {
	return &MaliciousPackageChecker{
		repository: repository,
	}, nil
}

// FetchAll downloads the malicious packages archive and returns all parsed packages
// and affected components without touching the database.
func buildFakePackages() ([]models.MaliciousPackage, []models.MaliciousAffectedComponent, []OSVEntry) {
	testPackages := map[string][]string{
		"npm":       {"fake-malicious-npm-package", "@fake-org/malicious-package"},
		"go":        {"github.com/fake-org/malicious-package"},
		"pypi":      {"fake-malicious-pypi-package"},
		"maven":     {"com.fake:malicious-package"},
		"crates.io": {"fake-malicious-crate"},
		"deb":       {"debian/fake-malicious-package"},
		// OCI names are fully qualified image references, as the OCI proxy looks them up.
		"oci": {"docker.io/fake-org/malicious-image"},
	}
	fakePurl := func(ecosystem, pkgName string) string {
		if ecosystem == "oci" {
			// pkg:oci/malicious-image?repository_url=docker.io/fake-org/malicious-image
			purl := normalize.OCIPurlFromImageReference(pkgName)
			return purl.ToString()
		}
		return fmt.Sprintf("pkg:%s/%s", ecosystem, pkgName)
	}

	packages := make([]models.MaliciousPackage, 0)
	affectedComponents := make([]models.MaliciousAffectedComponent, 0)
	osvEntries := make([]OSVEntry, 0)
	for ecosystem, pkgNames := range testPackages {
		for _, pkgName := range pkgNames {
			normalizedPkgName := strings.NewReplacer("/", "-", "@", "-", ":", "-", ".", "-").Replace(pkgName)
			fakeID := fmt.Sprintf("MAL-FAKE-TEST-%s-%s", strings.ToUpper(ecosystem), strings.ToUpper(normalizedPkgName))
			fakeEntry := &dtos.OSV{
				ID:      fakeID,
				Summary: fmt.Sprintf("Fake malicious %s package for testing", ecosystem),
				Details: "This is a fake malicious package entry used for testing the dependency proxy",
				Affected: []dtos.Affected{
					{
						Package: dtos.Package{
							Ecosystem: ecosystem,
							Name:      pkgName,
							Purl:      fakePurl(ecosystem, pkgName),
						},
						Versions: []string{},
					},
				},
				Published: time.Date(2024, 3, 22, 0, 0, 0, 0, time.UTC),
				Modified:  time.Date(2024, 3, 22, 0, 0, 0, 0, time.UTC),
			}
			osvEntries = append(osvEntries, OSVEntry{OSV: fakeEntry, ModifiedTimestamp: fakeEntry.Modified})
			packages = append(packages, models.MaliciousPackage{
				ID:        fakeID,
				Summary:   fakeEntry.Summary,
				Details:   fakeEntry.Details,
				Published: fakeEntry.Published,
				Modified:  fakeEntry.Published,
			})
			affectedComponents = append(affectedComponents, transformer.MaliciousAffectedComponentFromOSV(fakeEntry, fakeID)...)
		}
	}

	// The packages above are flagged for all versions, which lets a bare
	// "install <name>" be blocked before any version is resolved (see
	// checkMalicious in controller.go: it only blocks unconditionally when a
	// component affects all versions, and otherwise defers until a version is
	// known). That can't exercise the actual version-comparison logic, so each
	// ecosystem also gets a second fake package flagged at a specific version,
	// "v1.0.0", to prove equivalent-but-differently-spelled versions are
	// recognized as equal once a version is known (e.g. semver's "v1.0.0" vs
	// "1.0.0", or PEP 440's "v1.0.0" vs "1.0.0.0").
	versionedTestPackages := map[string]string{
		"npm":  "fake-malicious-npm-package-versioned",
		"go":   "github.com/fake-org/malicious-package-versioned",
		"pypi": "fake-malicious-pypi-package-versioned",
		// OCI tags are compared as versions too, so a distinct fake image lets
		// callers test tag-equivalence (e.g. "1.0.0" vs "v1.0.0") without
		// disturbing the "any tag is blocked" fixture above.
		"oci": "docker.io/fake-org/malicious-image-versioned",
	}
	for ecosystem, pkgName := range versionedTestPackages {
		normalizedPkgName := strings.NewReplacer("/", "-", "@", "-", ":", "-", ".", "-").Replace(pkgName)
		fakeID := fmt.Sprintf("MAL-FAKE-TEST-%s-%s", strings.ToUpper(ecosystem), strings.ToUpper(normalizedPkgName))
		fakeEntry := &dtos.OSV{
			ID:      fakeID,
			Summary: fmt.Sprintf("Fake malicious %s package (specific version) for testing", ecosystem),
			Details: "This is a fake malicious package entry, flagged at a specific version, used for testing version-comparison logic in the dependency proxy",
			Affected: []dtos.Affected{
				{
					Package: dtos.Package{
						Ecosystem: ecosystem,
						Name:      pkgName,
						Purl:      fakePurl(ecosystem, pkgName),
					},
					Versions: []string{"v1.0.0"},
				},
			},
			Published: time.Date(2024, 3, 22, 0, 0, 0, 0, time.UTC),
			Modified:  time.Date(2024, 3, 22, 0, 0, 0, 0, time.UTC),
		}
		osvEntries = append(osvEntries, OSVEntry{OSV: fakeEntry, ModifiedTimestamp: fakeEntry.Modified})
		packages = append(packages, models.MaliciousPackage{
			ID:        fakeID,
			Summary:   fakeEntry.Summary,
			Details:   fakeEntry.Details,
			Published: fakeEntry.Published,
			Modified:  fakeEntry.Published,
		})
		affectedComponents = append(affectedComponents, transformer.MaliciousAffectedComponentFromOSV(fakeEntry, fakeID)...)
	}

	return packages, affectedComponents, osvEntries
}

// insertMaliciousPackagesBulk streams malicious packages and components into staging tables. Call flushStagingTables once after all batches.
func insertMaliciousPackagesBulk(ctx context.Context, tx pgx.Tx, pkgs []models.MaliciousPackage, comps []models.MaliciousAffectedComponent, pkgTable, compTable string) error {
	if len(pkgs) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{pkgTable},
			[]string{"id", "content_hash", "summary", "details", "published", "modified"},
			pgx.CopyFromSlice(len(pkgs), func(i int) ([]any, error) {
				p := pkgs[i]
				return []any{p.ID, p.CalculateContentHash(), p.Summary, p.Details, p.Published, p.Modified}, nil
			})); err != nil {
			return fmt.Errorf("could not copy malicious packages into staging table: %w", err)
		}
	}
	if len(comps) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{compTable},
			[]string{"id", "malicious_package_id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"},
			pgx.CopyFromSlice(len(comps), func(i int) ([]any, error) {
				c := comps[i]
				return []any{c.ID, c.MaliciousPackageID, c.PurlWithoutVersion, c.Ecosystem, c.Version, c.SemverIntroduced, c.SemverFixed, c.VersionIntroduced, c.VersionFixed}, nil
			})); err != nil {
			return fmt.Errorf("could not copy malicious components into staging table: %w", err)
		}
	}
	return nil
}

func (c *MaliciousPackageChecker) GetMaliciousComponents(ctx context.Context, ecosystem, packageName string) ([]models.MaliciousAffectedComponent, error) {
	if packageName == "" {
		return nil, fmt.Errorf("packageName is required to check if a package is malicious")
	}

	var parsedPurl packageurl.PackageURL
	if strings.EqualFold(ecosystem, packageurl.TypeOCI) {
		// OCI package names are fully qualified image references (docker.io/library/nginx);
		// the spec-conform purl carries them in the repository_url qualifier.
		parsedPurl = normalize.OCIPurlFromImageReference(packageName)
	} else {
		purl := fmt.Sprintf("pkg:%s/%s", strings.ToLower(ecosystem), strings.ToLower(packageName))

		// Parse to normalize
		var err error
		parsedPurl, err = packageurl.FromString(purl)
		if err != nil {
			slog.Debug("Failed to parse purl", "purl", purl, "error", err)
			return nil, fmt.Errorf("failed to parse purl: %w", err)
		}
	}

	// Query database using purl matching (similar to PurlComparer)
	components, err := c.repository.GetMaliciousAffectedComponents(ctx, nil, parsedPurl)
	if err != nil {
		slog.Debug("Failed to query malicious packages", "error", err)
		return nil, fmt.Errorf("failed to query malicious packages: %w", err)
	}
	return components, nil
}

func (c *MaliciousPackageChecker) GetMaliciousPackage(ctx context.Context, id string) (models.MaliciousPackage, error) {
	return c.repository.GetMaliciousPackageByID(ctx, nil, id)
}
