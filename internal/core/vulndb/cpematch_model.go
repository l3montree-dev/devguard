package vulndb

import "strings"

type CPEMatch struct {
	ID        uint   `json:"-" gorm:"primaryKey;autoIncrement;"`
	Criteria  string `json:"criteria" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Part      string `json:"part" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Vendor    string `json:"vendor" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Product   string `json:"product" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Version   string `json:"version" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Update    string `json:"update" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Edition   string `json:"edition" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Language  string `json:"language" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	SwEdition string `json:"swEdition" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	TargetSw  string `json:"targetSw" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	TargetHw  string `json:"targetHw" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	Other     string `json:"other" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`

	VersionEndExcluding   string `json:"versionEndExcluding" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`
	VersionStartIncluding string `json:"versionStartIncluding" gorm:"uniqueIndex:idx_cpe;type:varchar(255);"`

	Vulnerable bool `json:"vulnerable" gorm:"type:boolean;"`

	CVEs []*CVE `json:"cve" gorm:"many2many:cve_cpe_match;"`
}

// criteria format:
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
func fromNVDCPEMatch(cpeMatch nvdCpeMatch) CPEMatch {
	// split the criteria into its parts
	parts := strings.Split(cpeMatch.Criteria, ":")

	return CPEMatch{
		Criteria:              cpeMatch.Criteria,
		Part:                  parts[2],
		Vendor:                parts[3],
		Product:               parts[4],
		Version:               parts[5],
		Update:                parts[6],
		Edition:               parts[7],
		Language:              parts[8],
		SwEdition:             parts[9],
		TargetSw:              parts[10],
		TargetHw:              parts[11],
		Other:                 parts[12],
		VersionEndExcluding:   cpeMatch.VersionEndIncluding,
		VersionStartIncluding: cpeMatch.VersionStartIncluding,
		Vulnerable:            cpeMatch.Vulnerable,
	}
}
