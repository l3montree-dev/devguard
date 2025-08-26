package models

import (
	"time"

	"github.com/google/uuid"
)

type AssetRiskDistribution struct {
	// the range of the risk - something like 2-4, 4-6, 6-8, 8-10
	Low      int `json:"low"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Critical int `json:"critical"`

	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	Label            string    `json:"label"`
}

type ArtifactRiskHistory struct {
	History
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;type:text;"`

	Artifact Artifact `json:"artifact" gorm:"foreignKey:AssetID,AssetVersionName,ArtifactName;references:AssetID,AssetVersionName,ArtifactName;constraint:OnDelete:CASCADE;"`
}

func (m ArtifactRiskHistory) TableName() string {
	return "asset_risk_history"
}

type Distribution struct {
	Low      int `json:"low"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Critical int `json:"critical"`

	LowCVSS      int `json:"lowCvss"`
	MediumCVSS   int `json:"mediumCvss"`
	HighCVSS     int `json:"highCvss"`
	CriticalCVSS int `json:"criticalCvss"`
}

type History struct {
	Distribution
	// on the day 2024-08-12 the asset had a sumRisk of 25.
	Day         time.Time `json:"day" gorm:"primaryKey;type:date"`
	SumOpenRisk float64   `json:"sumOpenRisk"`
	AvgOpenRisk float64   `json:"averageOpenRisk"`
	MaxOpenRisk float64   `json:"maxOpenRisk"`
	MinOpenRisk float64   `json:"minOpenRisk"`

	SumClosedRisk float64 `json:"sumClosedRisk"`
	AvgClosedRisk float64 `json:"averageClosedRisk"`
	MaxClosedRisk float64 `json:"maxClosedRisk"`
	MinClosedRisk float64 `json:"minClosedRisk"`

	OpenDependencyVulns  int `json:"openDependencyVulns"`
	FixedDependencyVulns int `json:"fixedDependencyVulns"`
}

type ProjectRiskHistory struct {
	Distribution
	History
	ProjectID uuid.UUID `json:"id" gorm:"primaryKey;type:uuid"`
}

func (m ProjectRiskHistory) TableName() string {
	return "project_risk_history"
}
