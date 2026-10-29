package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type ArtifactRiskHistory struct {
	History
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;type:text;"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
}

func (m ArtifactRiskHistory) TableName() string {
	return "artifact_risk_history"
}

type ArtifactRiskHistoryWithVersion struct {
	ArtifactRiskHistory
	Slug             string           `json:"slug" gorm:"column:slug"`
	DefaultBranch    bool             `json:"defaultBranch" gorm:"column:default_branch"`
	AssetVersionType AssetVersionType `json:"type" gorm:"column:type"`
}

type Distribution struct {
	Low      pq.StringArray `json:"low" gorm:"type:text[]"`
	High     pq.StringArray `json:"high" gorm:"type:text[]"`
	Medium   pq.StringArray `json:"medium" gorm:"type:text[]"`
	Critical pq.StringArray `json:"critical" gorm:"type:text[]"`

	FixableLow      pq.StringArray `json:"fixableLow" gorm:"type:text[]"`
	FixableMedium   pq.StringArray `json:"fixableMedium" gorm:"type:text[]"`
	FixableHigh     pq.StringArray `json:"fixableHigh" gorm:"type:text[]"`
	FixableCritical pq.StringArray `json:"fixableCritical" gorm:"type:text[]"`

	LowCVSS      pq.StringArray `json:"lowCvss" gorm:"type:text[]"` // dependencyVuln.id
	MediumCVSS   pq.StringArray `json:"mediumCvss" gorm:"type:text[]"`
	HighCVSS     pq.StringArray `json:"highCvss" gorm:"type:text[]"`
	CriticalCVSS pq.StringArray `json:"criticalCvss" gorm:"type:text[]"`

	FixableLowCVSS      pq.StringArray `json:"fixableLowCvss" gorm:"type:text[]"`
	FixableMediumCVSS   pq.StringArray `json:"fixableMediumCvss" gorm:"type:text[]"`
	FixableHighCVSS     pq.StringArray `json:"fixableHighCvss" gorm:"type:text[]"`
	FixableCriticalCVSS pq.StringArray `json:"fixableCriticalCvss" gorm:"type:text[]"`

	CVEPurlLow      pq.StringArray `json:"cvePurlLow" gorm:"type:text[]"` // dependencyVuln.cve_id
	CVEPurlMedium   pq.StringArray `json:"cvePurlMedium" gorm:"type:text[]"`
	CVEPurlHigh     pq.StringArray `json:"cvePurlHigh" gorm:"type:text[]"`
	CVEPurlCritical pq.StringArray `json:"cvePurlCritical" gorm:"type:text[]"`

	CVEPurlFixableLow      pq.StringArray `json:"cvePurlFixableLow" gorm:"type:text[]"`
	CVEPurlFixableMedium   pq.StringArray `json:"cvePurlFixableMedium" gorm:"type:text[]"`
	CVEPurlFixableHigh     pq.StringArray `json:"cvePurlFixableHigh" gorm:"type:text[]"`
	CVEPurlFixableCritical pq.StringArray `json:"cvePurlFixableCritical" gorm:"type:text[]"`

	CVEPurlLowCVSS      pq.StringArray `json:"cvePurlLowCvss" gorm:"type:text[]"`
	CVEPurlMediumCVSS   pq.StringArray `json:"cvePurlMediumCvss" gorm:"type:text[]"`
	CVEPurlHighCVSS     pq.StringArray `json:"cvePurlHighCvss" gorm:"type:text[]"`
	CVEPurlCriticalCVSS pq.StringArray `json:"cvePurlCriticalCvss" gorm:"type:text[]"`

	CVEPurlFixableLowCVSS      pq.StringArray `json:"cvePurlFixableLowCvss" gorm:"type:text[]"`
	CVEPurlFixableMediumCVSS   pq.StringArray `json:"cvePurlFixableMediumCvss" gorm:"type:text[]"`
	CVEPurlFixableHighCVSS     pq.StringArray `json:"cvePurlFixableHighCvss" gorm:"type:text[]"`
	CVEPurlFixableCriticalCVSS pq.StringArray `json:"cvePurlFixableCriticalCvss" gorm:"type:text[]"`
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
