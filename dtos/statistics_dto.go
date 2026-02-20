package dtos

import (
	"time"

	"github.com/google/uuid"
)

type DependencyVulnAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type DependencyVulnAggregationStateAndChange struct {
	Now DependencyVulnAggregationState `json:"now"`
	Was DependencyVulnAggregationState `json:"was"`
}

type OrgStructureDistribution struct {
	AmountOfProjects  int `json:"numProjects" gorm:"column:num_projects"`
	AmountOfAssets    int `json:"numAssets" gorm:"column:num_assets"`
	AmountOfArtifacts int `json:"numArtifacts" gorm:"column:num_artifacts"`
}

type ProjectRiskDistribution struct {
	ProjectName string `json:"projectName" gorm:"column:name"`
	Total       int    `json:"total" gorm:"column:total"`

	RiskDistribution
}

type AssetRiskDistribution struct {
	AssetName string `json:"assetName" gorm:"column:name"`
	Total     int    `json:"total" gorm:"column:total"`

	RiskDistribution
}

type ArtifactRiskDistribution struct {
	ArtifactName string `json:"artifactName" gorm:"column:artifactName"`
	Total        int    `json:"total" gorm:"column:total"`

	RiskDistribution
}

type RiskDistribution struct {
	LowRisk      int `json:"lowRisk" gorm:"column:risk_low"`
	MediumRisk   int `json:"mediumRisk" gorm:"column:risk_medium"`
	HighRisk     int `json:"highRisk" gorm:"column:risk_high"`
	CriticalRisk int `json:"criticalRisk" gorm:"column:risk_critical"`
}

type CVSSDistribution struct {
	LowCVSS      int `json:"lowCVSS" gorm:"column:cvss_low"`
	MediumCVSS   int `json:"mediumCVSS" gorm:"column:cvss_medium"`
	HighCVSS     int `json:"highCVSS" gorm:"column:cvss_high"`
	CriticalCVSS int `json:"criticalCVSS" gorm:"column:cvss_critical"`
}

type Distribution struct {
	RiskDistribution `json:"riskDistribution"`
	CVSSDistribution `json:"cvssDistribution"`
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

type RiskHistoryDTO struct {
	History
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;type:text;"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
}

type OrgOverview struct {
	VulnDistribution Distribution               `json:"vulnDistribution"`
	OrgStructure     OrgStructureDistribution   `json:"structure"`
	TopProjects      []ProjectRiskDistribution  `json:"topProjects"`
	TopAssets        []AssetRiskDistribution    `json:"topAssets"`
	TopArtifacts     []ArtifactRiskDistribution `json:"topArtifacts"`
}
