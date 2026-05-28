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

type Distribution struct {
	Low      int `json:"low"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Critical int `json:"critical"`

	FixableLow      int `json:"fixableLow"`
	FixableMedium   int `json:"fixableMedium"`
	FixableHigh     int `json:"fixableHigh"`
	FixableCritical int `json:"fixableCritical"`

	LowCVSS      int `json:"lowCvss"`
	MediumCVSS   int `json:"mediumCvss"`
	HighCVSS     int `json:"highCvss"`
	CriticalCVSS int `json:"criticalCvss"`

	FixableLowCVSS      int `json:"fixableLowCvss"`
	FixableMediumCVSS   int `json:"fixableMediumCvss"`
	FixableHighCVSS     int `json:"fixableHighCvss"`
	FixableCriticalCVSS int `json:"fixableCriticalCvss"`

	CVEPurlLow      int `json:"cvePurlLow"`
	CVEPurlMedium   int `json:"cvePurlMedium"`
	CVEPurlHigh     int `json:"cvePurlHigh"`
	CVEPurlCritical int `json:"cvePurlCritical"`

	CVEPurlFixableLow      int `json:"cvePurlFixableLow"`
	CVEPurlFixableMedium   int `json:"cvePurlFixableMedium"`
	CVEPurlFixableHigh     int `json:"cvePurlFixableHigh"`
	CVEPurlFixableCritical int `json:"cvePurlFixableCritical"`

	CVEPurlLowCVSS      int `json:"cvePurlLowCvss"`
	CVEPurlMediumCVSS   int `json:"cvePurlMediumCvss"`
	CVEPurlHighCVSS     int `json:"cvePurlHighCvss"`
	CVEPurlCriticalCVSS int `json:"cvePurlCriticalCvss"`

	CVEPurlFixableLowCVSS      int `json:"cvePurlFixableLowCVSS"`
	CVEPurlFixableMediumCVSS   int `json:"cvePurlFixableMediumCVSS"`
	CVEPurlFixableHighCVSS     int `json:"cvePurlFixableHighCVSS"`
	CVEPurlFixableCriticalCVSS int `json:"cvePurlFixableCriticalCVSS"`
}

type VulnSeverityDistribution struct {
	Low      int `json:"low"      gorm:"column:low_risk"`
	Medium   int `json:"medium"   gorm:"column:medium_risk"`
	High     int `json:"high"     gorm:"column:high_risk"`
	Critical int `json:"critical" gorm:"column:critical_risk"`

	LowCVSS      int `json:"lowCvss"      gorm:"column:low_cvss"`
	MediumCVSS   int `json:"mediumCvss"   gorm:"column:medium_cvss"`
	HighCVSS     int `json:"highCvss"     gorm:"column:high_cvss"`
	CriticalCVSS int `json:"criticalCvss" gorm:"column:critical_cvss"`
}

type ProjectVulnDistribution struct {
	Name string `json:"name" gorm:"column:pname"`
	Slug string `json:"slug" gorm:"column:pslug"`

	VulnSeverityDistribution
}

type AssetVulnDistribution struct {
	Name string `json:"name" gorm:"column:aname"`
	Slug string `json:"slug" gorm:"column:aslug"`

	VulnSeverityDistribution
}

type ArtifactVulnDistribution struct {
	Name             string `json:"name"             gorm:"column:name"`
	ProjectSlug      string `json:"projectSlug"      gorm:"column:project_slug"`
	AssetSlug        string `json:"assetSlug"        gorm:"column:asset_slug"`
	AssetVersionName string `json:"assetVersionName" gorm:"column:asset_version_name"`

	VulnSeverityDistribution
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

type RemediationTimeAverages struct {
	RiskAvgLow      float64 `json:"riskAvgLow"`
	RiskAvgMedium   float64 `json:"riskAvgMedium"`
	RiskAvgHigh     float64 `json:"riskAvgHigh"`
	RiskAvgCritical float64 `json:"riskAvgCritical"`

	CVSSAvgLow      float64 `json:"cvssAvgLow"`
	CVSSAvgMedium   float64 `json:"cvssAvgMedium"`
	CVSSAvgHigh     float64 `json:"cvssAvgHigh"`
	CVSSAvgCritical float64 `json:"cvssAvgCritical"`
}

type ComponentOccurrenceAcrossOrg struct {
	PackageURL       string `json:"purl" gorm:"column:purl"`
	TotalAmountInOrg int    `json:"totalAmount" gorm:"column:total_amount"`
}

type ComponentOccurrenceAcrossInstance struct {
	PackageURL     string  `json:"purl" gorm:"column:purl"`
	TotalAmount    int     `json:"totalAmount" gorm:"column:total_amount"`
	RelativeAmount float64 `json:"relativeAmount" gorm:"column:relative_amount"`
}

type CVEOccurrence struct {
	CVEID            string  `json:"cveID" gorm:"column:cve_id"`
	CVSS             float32 `json:"cvss" gorm:"column:cvss"`
	TotalAmountInOrg int     `json:"totalAmount" gorm:"column:total_amount"`
}

type VulnEventAverage struct {
	VulnEventType VulnEventType `gorm:"column:type"`
	Average       float32       `gorm:"column:average"`
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
	Distribution
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

type EcosystemUsage struct {
	Ecosystem      string  `json:"ecosystem"      gorm:"column:ecosystem"`
	TotalCount     int     `json:"absoluteAmount" gorm:"column:absolute"`
	RelativeAmount float32 `json:"relativeAmount" gorm:"column:percentage"`
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

// average remediation times for remediated vulns in org
// as well as the average age of all non remediated ('open') vulns
type AverageRemediationTimes struct {
	// average time until vulns are remediated
	LowRiskRemediated      float64 `json:"lowRiskRemediated"      gorm:"column:low_risk_remediated"`
	MediumRiskRemediated   float64 `json:"mediumRiskRemediated"   gorm:"column:medium_risk_remediated"`
	HighRiskRemediated     float64 `json:"highRiskRemediated"     gorm:"column:high_risk_remediated"`
	CriticalRiskRemediated float64 `json:"criticalRiskRemediated" gorm:"column:critical_risk_remediated"`

	LowCVSSRemediated      float64 `json:"lowCVSSRemediated"      gorm:"column:low_cvss_remediated"`
	MediumCVSSRemediated   float64 `json:"mediumCVSSRemediated"   gorm:"column:medium_cvss_remediated"`
	HighCVSSRemediated     float64 `json:"highCVSSRemediated"     gorm:"column:high_cvss_remediated"`
	CriticalCVSSRemediated float64 `json:"criticalCVSSRemediated" gorm:"column:critical_cvss_remediated"`

	// average age of non remediated (open) vulns
	LowRiskOpen      float64 `json:"lowRiskOpen"      gorm:"column:low_risk_open"`
	MediumRiskOpen   float64 `json:"mediumRiskOpen"   gorm:"column:medium_risk_open"`
	HighRiskOpen     float64 `json:"highRiskOpen"     gorm:"column:high_risk_open"`
	CriticalRiskOpen float64 `json:"criticalRiskOpen" gorm:"column:critical_risk_open"`

	LowCVSSOpen      float64 `json:"lowCVSSOpen"      gorm:"column:low_cvss_open"`
	MediumCVSSOpen   float64 `json:"mediumCVSSOpen"   gorm:"column:medium_cvss_open"`
	HighCVSSOpen     float64 `json:"highCVSSOpen"     gorm:"column:high_cvss_open"`
	CriticalCVSSOpen float64 `json:"criticalCVSSOpen" gorm:"column:critical_cvss_open"`
}

type OrgOverview struct {
	VulnDistribution VulnSeverityDistribution `json:"vulnDistribution"`

	OrgStructure OrgStructureDistribution   `json:"structure"`
	TopProjects  []ProjectVulnDistribution  `json:"topProjects"`
	TopAssets    []AssetVulnDistribution    `json:"topAssets"`
	TopArtifacts []ArtifactVulnDistribution `json:"topArtifacts"`

	TopComponents []ComponentOccurrenceAcrossOrg `json:"topComponents"`
	TopCVEs       []CVEOccurrence                `json:"topCVEs"`

	VulnEventAverage AverageVulnEventsPerWeek `json:"vulnEventAverage"`
	OrgRiskHistory   []OrgRiskHistory         `json:"orgRiskHistory"`

	AverageOpenCodeRisksPerProject float32          `json:"averageOpenCodeRisksPerProject"`
	TopEcosystems                  []EcosystemUsage `json:"topEcosystems"`

	MaliciousPackages        []MaliciousPackageInOrg `json:"maliciousPackages"`
	AverageAgeOfDependencies time.Duration           `json:"averageAgeOfDependencies" swaggertype:"integer"`
	AverageRemediationTimes  AverageRemediationTimes `json:"averageRemediationTimes"`

	RemediationTypeDistribution RemediationTypeDistribution `json:"remediationTypeDistribution"`
}

type InstanceUsageStatistics struct {
	NumberOfUsers                         int `gorm:"column:number_of_users"`
	NumberOfOrganizations                 int `gorm:"column:number_of_organizations"`
	NumberOfProjects                      int `gorm:"column:number_of_projects"`
	NumberOfAssetVersions                 int `gorm:"column:number_of_asset_versions"`
	NumberOfTicketSyncedProjects          int `gorm:"column:number_of_ticket_synced_projects"`
	NumberOfProjectsWithGitlabIntegration int `gorm:"column:number_of_projects_with_gitlab_integration"`
}
