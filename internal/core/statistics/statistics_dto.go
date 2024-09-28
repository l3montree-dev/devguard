package statistics

import (
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type FlawAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type FlawAggregationStateAndChange struct {
	Now FlawAggregationState `json:"now"`
	Was FlawAggregationState `json:"was"`
}

type AssetRiskHistory struct {
	Asset       models.Asset              `json:"asset"`
	RiskHistory []models.AssetRiskHistory `json:"riskHistory"`
}

type ProjectRiskHistory struct {
	Project     models.Project              `json:"project"`
	RiskHistory []models.ProjectRiskHistory `json:"riskHistory"`
}
