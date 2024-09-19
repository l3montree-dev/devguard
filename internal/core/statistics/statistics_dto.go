package statistics

import (
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type flawAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type flawAggregationStateAndChange struct {
	Now flawAggregationState `json:"now"`
	Was flawAggregationState `json:"was"`
}

type assetRiskHistory struct {
	Asset       models.Asset              `json:"asset"`
	RiskHistory []models.AssetRiskHistory `json:"riskHistory"`
}

type projectRiskHistory struct {
	Project     models.Project              `json:"project"`
	RiskHistory []models.ProjectRiskHistory `json:"riskHistory"`
}
