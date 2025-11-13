package dtos

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
)

type DependencyVulnAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type DependencyVulnAggregationStateAndChange struct {
	Now DependencyVulnAggregationState `json:"now"`
	Was DependencyVulnAggregationState `json:"was"`
}

type RiskHistoryDTO struct {
	models.History
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;type:text;"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
}

func fromModelToRiskHistoryDTO(history models.ArtifactRiskHistory) RiskHistoryDTO {
	return RiskHistoryDTO{
		History:          history.History,
		ArtifactName:     history.ArtifactName,
		AssetVersionName: history.AssetVersionName,
		AssetID:          history.AssetID,
	}
}
