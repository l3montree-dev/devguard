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

type VulnDistributionInStructure struct {
	Name             string  `json:"name" gorm:"column:name"`
	Slug             string  `json:"slug" gorm:"column:slug"`
	ProjectSlug      *string `json:"projectSlug" gorm:"column:project_slug"`
	AssetSlug        *string `json:"assetSlug" gorm:"column:asset_slug"`
	AssetVersionName *string `json:"assetVersionName" gorm:"column:asset_version_name"`

	VulnDistribution
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

type VulnDistribution struct {
	RiskDistribution
	CVSSDistribution
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

	CVEPurlLow      int `json:"cvePurlLow"`
	CVEPurlMedium   int `json:"cvePurlMedium"`
	CVEPurlHigh     int `json:"cvePurlHigh"`
	CVEPurlCritical int `json:"cvePurlCritical"`

	CVEPurlLowCVSS      int `json:"cvePurlLowCvss"`
	CVEPurlMediumCVSS   int `json:"cvePurlMediumCvss"`
	CVEPurlHighCVSS     int `json:"cvePurlHighCvss"`
	CVEPurlCriticalCVSS int `json:"cvePurlCriticalCvss"`
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

type ComponentUsageAcrossOrg struct {
	PackageURL       string `json:"purl" gorm:"column:purl"`
	TotalAmountInOrg string `json:"totalAmount" gorm:"column:total_amount"`
}

type CVEOccurrencesAcrossOrg struct {
	PackageURL       string `json:"cveID" gorm:"column:cve_id"`
	TotalAmountInOrg string `json:"totalAmount" gorm:"column:total_amount"`
}

type VulnEventAverage struct {
	VulnEventType VulnEventType `gorm:"column:type"`
	Average       float32       `gorm:"column:weekly_average"`
}

type AverageVulnEventsPerWeek struct {
	AverageDetectedEvents      float32 `json:"averageDetectedEvents"`
	AverageReopenedEvents      float32 `json:"averageReopenedEvents"`
	AverageFalsePositiveEvents float32 `json:"averageFalsePositiveEvents"`
	AverageAcceptedEvents      float32 `json:"averageAcceptedEvents"`
	AverageFixedEvents         float32 `json:"averageFixedEvents"`
}

type OrgOverview struct {
	VulnDistribution VulnDistribution `json:"vulnDistribution"`

	OrgStructure OrgStructureDistribution      `json:"structure"`
	TopProjects  []VulnDistributionInStructure `json:"topProjects"`
	TopAssets    []VulnDistributionInStructure `json:"topAssets"`
	TopArtifacts []VulnDistributionInStructure `json:"topArtifacts"`

	TopComponents []ComponentUsageAcrossOrg `json:"topComponents"`
	TopCVEs       []CVEOccurrencesAcrossOrg `json:"topCVEs"`

	VulnEventAverage AverageVulnEventsPerWeek `json:"vulnEventAverage"`
}
