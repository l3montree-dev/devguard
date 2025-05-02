// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package asset

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type service struct {
	assetRepository          core.AssetRepository
	dependencyVulnRepository core.DependencyVulnRepository
	dependencyVulnService    core.DependencyVulnService
	httpClient               *http.Client
}

func NewService(assetRepository core.AssetRepository, dependencyVulnRepository core.DependencyVulnRepository, dependencyVulnService core.DependencyVulnService) *service {
	return &service{
		assetRepository:          assetRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		httpClient:               &http.Client{},
	}
}

func (s *service) GetByAssetID(assetID uuid.UUID) (models.Asset, error) {
	return s.assetRepository.Read(assetID)
}

func (s *service) UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error {
	err := s.dependencyVulnRepository.Transaction(func(tx core.DB) error {

		err := s.assetRepository.Save(tx, &asset)
		if err != nil {
			slog.Info("error saving asset", "err", err)
			return fmt.Errorf("could not save asset: %v", err)
		}
		// get the dependencyVulns
		dependencyVulns, err := s.dependencyVulnRepository.GetAllVulnsByAssetID(tx, asset.GetID())
		if err != nil {
			slog.Info("error getting dependencyVulns", "err", err)
			return fmt.Errorf("could not get dependencyVulns: %v", err)
		}

		err = s.dependencyVulnService.RecalculateRawRiskAssessment(tx, responsible, dependencyVulns, justification, asset)
		if err != nil {
			slog.Info("error updating raw risk assessment", "err", err)
			return fmt.Errorf("could not update raw risk assessment: %v", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("could not update asset: %v", err)
	}

	return nil
}

func (s *service) GetBadgeSVG(CVSS models.AssetRiskDistribution) string {
	labelWidth := 40
	boxWidth := 25
	boxHeight := 20

	// Define colors
	colors := map[string]string{
		"C": "#8B0000",
		"H": "#B22222",
		"M": "#CD5C5C",
		"L": "#F08080",
	}

	totalWidth := labelWidth + 4*boxWidth

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" role="img" aria-label="CVSS">`, totalWidth, boxHeight))

	// Gradient and clip path
	sb.WriteString(`<linearGradient id="s" x2="0" y2="100%">
	<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
	<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<clipPath id="r"><rect width="` + fmt.Sprintf("%d", totalWidth) + `" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">`)

	// Label background
	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#000"/>`, labelWidth, boxHeight))

	// Values
	values := []struct {
		Key   string
		Value int
	}{
		{"C", CVSS.Critical},
		{"H", CVSS.High},
		{"M", CVSS.Medium},
		{"L", CVSS.Low},
	}

	for i, val := range values {
		x := labelWidth + i*boxWidth
		color := colors[val.Key]
		sb.WriteString(fmt.Sprintf(`<rect x="%d" width="%d" height="%d" fill="%s"/>`, x, boxWidth, boxHeight, color))
	}

	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="url(#s)"/>`, totalWidth, boxHeight))
	sb.WriteString(`</g>`)

	// TEXT
	sb.WriteString(`<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">`)

	// Label
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d">%s</text>`, 4, 14, "CVSS"))

	// Values with padding
	for i, val := range values {
		x := labelWidth + i*boxWidth + 3 // 3px horizontal padding
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d">%s:%d</text>`, x, 14, val.Key, val.Value))
	}

	sb.WriteString(`</g></svg>`)

	return sb.String()
}
