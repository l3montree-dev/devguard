package statistics

import (
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type DependencyVulnAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type DependencyVulnAggregationStateAndChange struct {
	Now DependencyVulnAggregationState `json:"now"`
	Was DependencyVulnAggregationState `json:"was"`
}

type AssetRiskHistory struct {
	Asset       models.Asset                 `json:"asset"`
	RiskHistory []models.ArtifactRiskHistory `json:"riskHistory"`
}

type ProjectRiskHistory struct {
	Project     models.Project              `json:"project"`
	RiskHistory []models.ProjectRiskHistory `json:"riskHistory"`
}
