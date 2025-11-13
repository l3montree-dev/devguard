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
				Low:          history.History.Distribution.Low,
				High:         history.History.Distribution.High,
				Medium:       history.History.Distribution.Medium,
				Critical:     history.History.Distribution.Critical,
				LowCVSS:      history.History.Distribution.LowCVSS,
				MediumCVSS:   history.History.Distribution.MediumCVSS,
				HighCVSS:     history.History.Distribution.HighCVSS,
				CriticalCVSS: history.History.Distribution.CriticalCVSS,
			},
			Day:                  history.History.Day,
			SumOpenRisk:          history.History.SumOpenRisk,
			AvgOpenRisk:          history.History.AvgOpenRisk,
			MaxOpenRisk:          history.History.MaxOpenRisk,
			MinOpenRisk:          history.History.MinOpenRisk,
			SumClosedRisk:        history.History.SumClosedRisk,
			AvgClosedRisk:        history.History.AvgClosedRisk,
			MaxClosedRisk:        history.History.MaxClosedRisk,
			MinClosedRisk:        history.History.MinClosedRisk,
			OpenDependencyVulns:  history.History.OpenDependencyVulns,
			FixedDependencyVulns: history.History.FixedDependencyVulns,
		},
		ArtifactName:     history.ArtifactName,
		AssetVersionName: history.AssetVersionName,
		AssetID:          history.AssetID,
	}
}
