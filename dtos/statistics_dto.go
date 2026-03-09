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
	CVEID            string  `json:"cveID" gorm:"column:cve_id"`
	CVSS             float32 `json:"cvss" gorm:"cvss"`
	TotalAmountInOrg string  `json:"totalAmount" gorm:"column:total_amount"`
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

type OrgRiskHistory struct {
	Day time.Time `json:"day" gorm:"column:day"`

	LowRisk      int `json:"lowRisk" gorm:"column:low_risk"`
	HighRisk     int `json:"highRisk" gorm:"column:high_risk"`
	MediumRisk   int `json:"mediumRisk" gorm:"column:medium_risk"`
	CriticalRisk int `json:"criticalRisk" gorm:"column:critical_risk"`

	LowCVSS      int `json:"lowCVSS" gorm:"column:low_cvss"`
	MediumCVSS   int `json:"mediumCVSS" gorm:"column:medium_cvss"`
	HighCVSS     int `json:"highCVSS" gorm:"column:high_cvss"`
	CriticalCVSS int `json:"criticalCVSS" gorm:"column:critical_cvss"`
}

type ProjectVulnCountAverageBySeverity struct {
	RiskLowAverage      float32 `json:"riskLowAverage" gorm:"column:risk_low_average"`
	RiskMediumAverage   float32 `json:"riskMediumAverage" gorm:"column:risk_medium_average"`
	RiskHighAverage     float32 `json:"riskHighAverage" gorm:"column:risk_high_average"`
	RiskCriticalAverage float32 `json:"riskCriticalAverage" gorm:"column:risk_critical_average"`
	CVSSLowAverage      float32 `json:"cvssLowAverage" gorm:"column:cvss_low_average"`
	CVSSMediumAverage   float32 `json:"cvssMediumAverage" gorm:"column:cvss_medium_average"`
	CVSSHighAverage     float32 `json:"cvssHighAverage" gorm:"column:cvss_high_average"`
	CVSSCriticalAverage float32 `json:"cvssCriticalAverage" gorm:"column:cvss_critical_average"`
}

type ComponentOccurrenceCount struct {
	DependencyID string `gorm:"column:dependency_id"`
	Count        int    `gorm:"column:count"`
}

type EcosystemUsage struct {
	Ecosystem      string  `json:"ecosystem"`
	TotalCount     int     `json:"totalCount"`
	RelativeAmount float32 `json:"relativeAmount"`
}

type MaliciousPackageInOrg struct {
	ProjectName        string `json:"projectName"`
	AssetName          string `json:"assetName"`
	AssetVersionName   string `json:"assetVersionName"`
	Component          string `json:"component"`
	MaliciousPackageID string `json:"maliciousPackageID"`
}

type RemediationTypeDistributionRow struct {
	Type       string
	Percentage float64
}

type RemediationTypeDistribution struct {
	AcceptedPercentage      float64 `json:"acceptedPercentage" `
	FalsePositivePercentage float64 `json:"falsePositivePercentage"`
	FixedPercentage         float64 `json:"fixedPercentage"`
}

type AverageRemediationTimes struct {
	LowRiskAverage      float64 `json:"lowRiskAverage" gorm:"column:low_risk_average"`
	MediumRiskAverage   float64 `json:"mediumRiskAverage" gorm:"column:medium_risk_average"`
	HighRiskAverage     float64 `json:"highRiskAverage" gorm:"column:high_risk_average"`
	CriticalRiskAverage float64 `json:"criticalRiskAverage" gorm:"column:critical_risk_average"`

	LowCVSSAverage      float64 `json:"lowCVSSAverage" gorm:"column:low_cvss_average"`
	MediumCVSSAverage   float64 `json:"mediumCVSSAverage" gorm:"column:medium_cvss_average"`
	HighCVSSAverage     float64 `json:"highCVSSAverage" gorm:"column:high_cvss_average"`
	CriticalCVSSAverage float64 `json:"criticalCVSSAverage" gorm:"column:critical_cvss_average"`
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
	OrgRiskHistory   []OrgRiskHistory         `json:"orgRiskHistory"`

	AverageOpenCodeRisksPerProject float32                           `json:"averageOpenCodeRisksPerProject"`
	ProjectOpenVulnAverage         ProjectVulnCountAverageBySeverity `json:"projectOpenVulnAverage"`
	TopEcosystems                  []EcosystemUsage                  `json:"topEcosystems"`

	MaliciousPackages        []MaliciousPackageInOrg `json:"maliciousPackages"`
	AverageAgeOfDependencies time.Duration           `json:"averageAgeOfDependencies"`
	AverageRemediationTimes  AverageRemediationTimes `json:"averageRemediationTimes"`

	RemediationTypeDistribution RemediationTypeDistribution `json:"remediationTypeDistribution"`
}
