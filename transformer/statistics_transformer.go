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

package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func DistributionToDTO(distribution models.Distribution) dtos.Distribution {
	return dtos.Distribution{
		Low:             len(distribution.Low),
		High:            len(distribution.High),
		Medium:          len(distribution.Medium),
		Critical:        len(distribution.Critical),
		FixableLow:      len(distribution.FixableLow),
		FixableMedium:   len(distribution.FixableMedium),
		FixableHigh:     len(distribution.FixableHigh),
		FixableCritical: len(distribution.FixableCritical),

		LowCVSS:             len(distribution.LowCVSS),
		MediumCVSS:          len(distribution.MediumCVSS),
		HighCVSS:            len(distribution.HighCVSS),
		CriticalCVSS:        len(distribution.CriticalCVSS),
		FixableLowCVSS:      len(distribution.FixableLowCVSS),
		FixableMediumCVSS:   len(distribution.FixableMediumCVSS),
		FixableHighCVSS:     len(distribution.FixableHighCVSS),
		FixableCriticalCVSS: len(distribution.FixableCriticalCVSS),

		CVEPurlLow:             len(distribution.CVEPurlLow),
		CVEPurlMedium:          len(distribution.CVEPurlMedium),
		CVEPurlHigh:            len(distribution.CVEPurlHigh),
		CVEPurlCritical:        len(distribution.CVEPurlCritical),
		CVEPurlFixableLow:      len(distribution.CVEPurlFixableLow),
		CVEPurlFixableMedium:   len(distribution.CVEPurlFixableMedium),
		CVEPurlFixableHigh:     len(distribution.CVEPurlFixableHigh),
		CVEPurlFixableCritical: len(distribution.CVEPurlFixableCritical),

		CVEPurlLowCVSS:             len(distribution.CVEPurlLowCVSS),
		CVEPurlMediumCVSS:          len(distribution.CVEPurlMediumCVSS),
		CVEPurlHighCVSS:            len(distribution.CVEPurlHighCVSS),
		CVEPurlCriticalCVSS:        len(distribution.CVEPurlCriticalCVSS),
		CVEPurlFixableLowCVSS:      len(distribution.CVEPurlFixableLowCVSS),
		CVEPurlFixableMediumCVSS:   len(distribution.CVEPurlFixableMediumCVSS),
		CVEPurlFixableHighCVSS:     len(distribution.CVEPurlFixableHighCVSS),
		CVEPurlFixableCriticalCVSS: len(distribution.CVEPurlFixableCriticalCVSS),

		UniqueCrossArtifactLow:      len(utils.UniqBy(distribution.Low, func(x string) string { return x })),
		UniqueCrossArtifactHigh:     len(utils.UniqBy(distribution.High, func(x string) string { return x })),
		UniqueCrossArtifactMedium:   len(utils.UniqBy(distribution.Medium, func(x string) string { return x })),
		UniqueCrossArtifactCritical: len(utils.UniqBy(distribution.Critical, func(x string) string { return x })),

		UniqueCrossArtifactFixableLow:      len(utils.UniqBy(distribution.FixableLow, func(x string) string { return x })),
		UniqueCrossArtifactFixableMedium:   len(utils.UniqBy(distribution.FixableMedium, func(x string) string { return x })),
		UniqueCrossArtifactFixableHigh:     len(utils.UniqBy(distribution.FixableHigh, func(x string) string { return x })),
		UniqueCrossArtifactFixableCritical: len(utils.UniqBy(distribution.FixableCritical, func(x string) string { return x })),

		UniqueCrossArtifactLowCVSS:      len(utils.UniqBy(distribution.LowCVSS, func(x string) string { return x })),
		UniqueCrossArtifactMediumCVSS:   len(utils.UniqBy(distribution.MediumCVSS, func(x string) string { return x })),
		UniqueCrossArtifactHighCVSS:     len(utils.UniqBy(distribution.HighCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCriticalCVSS: len(utils.UniqBy(distribution.CriticalCVSS, func(x string) string { return x })),

		UniqueCrossArtifactFixableLowCVSS:      len(utils.UniqBy(distribution.FixableLowCVSS, func(x string) string { return x })),
		UniqueCrossArtifactFixableMediumCVSS:   len(utils.UniqBy(distribution.FixableMediumCVSS, func(x string) string { return x })),
		UniqueCrossArtifactFixableHighCVSS:     len(utils.UniqBy(distribution.FixableHighCVSS, func(x string) string { return x })),
		UniqueCrossArtifactFixableCriticalCVSS: len(utils.UniqBy(distribution.FixableCriticalCVSS, func(x string) string { return x })),

		UniqueCrossArtifactCVEPurlLow:      len(utils.UniqBy(distribution.CVEPurlLow, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlMedium:   len(utils.UniqBy(distribution.CVEPurlMedium, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlHigh:     len(utils.UniqBy(distribution.CVEPurlHigh, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlCritical: len(utils.UniqBy(distribution.CVEPurlCritical, func(x string) string { return x })),

		UniqueCrossArtifactCVEPurlFixableLow:      len(utils.UniqBy(distribution.CVEPurlFixableLow, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableMedium:   len(utils.UniqBy(distribution.CVEPurlFixableMedium, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableHigh:     len(utils.UniqBy(distribution.CVEPurlFixableHigh, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableCritical: len(utils.UniqBy(distribution.CVEPurlFixableCritical, func(x string) string { return x })),

		UniqueCrossArtifactCVEPurlLowCVSS:      len(utils.UniqBy(distribution.CVEPurlLowCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlMediumCVSS:   len(utils.UniqBy(distribution.CVEPurlMediumCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlHighCVSS:     len(utils.UniqBy(distribution.CVEPurlHighCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlCriticalCVSS: len(utils.UniqBy(distribution.CVEPurlCriticalCVSS, func(x string) string { return x })),

		UniqueCrossArtifactCVEPurlFixableLowCVSS:      len(utils.UniqBy(distribution.CVEPurlFixableLowCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableMediumCVSS:   len(utils.UniqBy(distribution.CVEPurlFixableMediumCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableHighCVSS:     len(utils.UniqBy(distribution.CVEPurlFixableHighCVSS, func(x string) string { return x })),
		UniqueCrossArtifactCVEPurlFixableCriticalCVSS: len(utils.UniqBy(distribution.CVEPurlFixableCriticalCVSS, func(x string) string { return x })),

		DiffAddedDependencyVulns:   distribution.DiffAddedDependencyVulns,
		DiffRemovedDependencyVulns: distribution.DiffRemovedDependencyVulns,
	}
}

func ArtifactRiskHistoryToDTO(history models.ArtifactRiskHistory) dtos.RiskHistory {
	return dtos.RiskHistory{
		History: dtos.History{
			Distribution:         DistributionToDTO(history.Distribution),
			Day:                  history.Day,
			SumOpenRisk:          history.SumOpenRisk,
			AvgOpenRisk:          history.AvgOpenRisk,
			MaxOpenRisk:          history.MaxOpenRisk,
			MinOpenRisk:          history.MinOpenRisk,
			SumClosedRisk:        history.SumClosedRisk,
			AvgClosedRisk:        history.AvgClosedRisk,
			MaxClosedRisk:        history.MaxClosedRisk,
			MinClosedRisk:        history.MinClosedRisk,
			OpenDependencyVulns:  history.OpenDependencyVulns,
			FixedDependencyVulns: history.FixedDependencyVulns,
		},
		ArtifactName:     history.ArtifactName,
		AssetVersionName: history.AssetVersionName,
		AssetID:          history.AssetID,
	}
}

func ArtifactRiskHistoryWithVersionToDTO(history models.ArtifactRiskHistoryWithVersion) dtos.RiskHistoryWithVersion {
	return dtos.RiskHistoryWithVersion{
		RiskHistory:      ArtifactRiskHistoryToDTO(history.ArtifactRiskHistory),
		Slug:             history.Slug,
		DefaultBranch:    history.DefaultBranch,
		AssetVersionType: string(history.AssetVersionType),
	}
}
