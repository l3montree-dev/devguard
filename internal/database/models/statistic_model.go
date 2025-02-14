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

	ID    uuid.UUID `json:"id" gorm:"primaryKey;type:uuid"`
	Label string    `json:"label"`
}

type AssetRiskHistory struct {
	AssetID uuid.UUID `json:"id" gorm:"primaryKey;type:uuid"`
	// on the day 2024-08-12 the asset had a sumRisk of 25.
	Day time.Time `json:"day" gorm:"primaryKey;type:date"`

	SumOpenRisk float64 `json:"sumOpenRisk"`
	AvgOpenRisk float64 `json:"averageOpenRisk"`
	MaxOpenRisk float64 `json:"maxOpenRisk"`
	MinOpenRisk float64 `json:"minOpenRisk"`

	SumClosedRisk float64 `json:"sumClosedRisk"`
	AvgClosedRisk float64 `json:"averageClosedRisk"`
	MaxClosedRisk float64 `json:"maxClosedRisk"`
	MinClosedRisk float64 `json:"minClosedRisk"`

	OpenDependencyVulns  int `json:"openDependencyVulns"`
	FixedDependencyVulns int `json:"fixedDependencyVulns"`
}

func (m AssetRiskHistory) TableName() string {
	return "asset_risk_history"
}

type ProjectRiskHistory struct {
	ProjectID uuid.UUID `json:"id" gorm:"primaryKey;type:uuid"`
	// on the day 2024-08-12 the asset had a sumRisk of 25.
	Day time.Time `json:"day" gorm:"primaryKey;type:date"`

	SumOpenRisk float64 `json:"sumOpenRisk"`
	AvgOpenRisk float64 `json:"averageOpenRisk"`
	MaxOpenRisk float64 `json:"maxOpenRisk"`
	MinOpenRisk float64 `json:"minOpenRisk"`

	SumClosedRisk float64 `json:"sumClosedRisk"`
	AvgClosedRisk float64 `json:"averageClosedRisk"`
	MaxClosedRisk float64 `json:"maxClosedRisk"`
	MinClosedRisk float64 `json:"minClosedRisk"`

	OpenDependencyVulns  int `json:"openDependencyVulns"`
	FixedDependencyVulns int `json:"fixedDependencyVulns"`
}

func (m ProjectRiskHistory) TableName() string {
	return "project_risk_history"
}
