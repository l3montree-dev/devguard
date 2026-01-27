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
)

func ArtifactRiskHistoryToDTO(history models.ArtifactRiskHistory) dtos.RiskHistoryDTO {
	return dtos.RiskHistoryDTO{
		History: dtos.History{
			Distribution: dtos.Distribution{
				Low:          history.Low,
				High:         history.High,
				Medium:       history.Medium,
				Critical:     history.Critical,
				LowCVSS:      history.LowCVSS,
				MediumCVSS:   history.MediumCVSS,
				HighCVSS:     history.HighCVSS,
				CriticalCVSS: history.CriticalCVSS,

				UniqueLow:      history.UniqueLow,
				UniqueMedium:   history.UniqueMedium,
				UniqueHigh:     history.UniqueHigh,
				UniqueCritical: history.UniqueCritical,
				UniqueLowCVSS:      history.UniqueLowCVSS,
				UniqueMediumCVSS:   history.UniqueMediumCVSS,
				UniqueHighCVSS:     history.UniqueHighCVSS,
				UniqueCriticalCVSS: history.UniqueCriticalCVSS,
			},
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
