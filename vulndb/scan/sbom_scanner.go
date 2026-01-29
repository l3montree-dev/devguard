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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package scan

import (
	"log/slog"
	"sync"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
)

type sbomScanner struct {
	purlComparer comparer
}

// the vulnInPackage interface is used to abstract the different types of vulnerabilities
// it includes more than just the CVE ID to allow for more detailed information
// like the affected package version and fixed version

type comparer interface {
	GetVulns(purl packageurl.PackageURL) ([]models.VulnInPackage, error)
}

func NewSBOMScanner(purlComparer comparer, cveRepository shared.CveRepository) *sbomScanner {
	return &sbomScanner{
		purlComparer: purlComparer,
	}
}

func (s *sbomScanner) Scan(bom *normalize.SBOMGraph) ([]models.VulnInPackage, error) {
	// Collect all PURLs first
	var purls []packageurl.PackageURL
	for c := range bom.NodesOfType(normalize.GraphNodeTypeComponent) {
		if c.Component.PackageURL != "" {
			parsed, err := packageurl.FromString(c.Component.PackageURL)
			if err != nil {
				slog.Warn("could not parse purl", "purl", c.Component.PackageURL, "err", err)
				continue
			}
			purls = append(purls, parsed)
		}
	}

	if len(purls) == 0 {
		return []models.VulnInPackage{}, nil
	}

	// Query vulnerabilities in parallel (10 concurrent workers)
	results := make([][]models.VulnInPackage, len(purls))
	sem := make(chan struct{}, 10) // Limit concurrency
	errChan := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		var wg sync.WaitGroup
		for i, purl := range purls {
			wg.Add(1)
			go func(idx int, p packageurl.PackageURL) {
				defer wg.Done()
				sem <- struct{}{}        // Acquire
				defer func() { <-sem }() // Release

				vulns, err := s.purlComparer.GetVulns(p)
				if err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
				results[idx] = vulns
			}(i, purl)
		}
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errChan:
		return nil, err
	case <-done:
	}

	// Collect all vulnerabilities
	allVulns := make([]models.VulnInPackage, 0, len(purls))
	for _, vulns := range results {
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}
