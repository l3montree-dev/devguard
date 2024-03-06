package vulndb

import "strings"

type CPEMatch struct {
	MatchCriteriaID string `json:"matchCriteriaId" gorm:"primaryKey;type:text;"`
	Criteria        string `json:"criteria" gorm:"type:text;"`
	Part            string `json:"part" gorm:"type:text;"`
	Vendor          string `json:"vendor" gorm:"type:text;"`
	Product         string `json:"product" gorm:"type:text;"`
	Version         string `json:"version" gorm:"type:text;"`
	Update          string `json:"update" gorm:"type:text;"`
	Edition         string `json:"edition" gorm:"type:text;"`
	Language        string `json:"language" gorm:"type:text;"`
	SwEdition       string `json:"swEdition" gorm:"type:text;"`
	TargetSw        string `json:"targetSw" gorm:"type:text;"`
	TargetHw        string `json:"targetHw" gorm:"type:text;"`
	Other           string `json:"other" gorm:"type:text;"`

	VersionEndExcluding   string `json:"versionEndExcluding" gorm:"type:text;"`
	VersionStartIncluding string `json:"versionStartIncluding" gorm:"type:text;"`

	Vulnerable bool `json:"vulnerable" gorm:"type:boolean;"`

	CVEs []*CVE `json:"cve" gorm:"many2many:cve_cpe_match;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// criteria format:
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
func fromNVDCPEMatch(cpeMatch nvdCpeMatch) CPEMatch {
	// split the criteria into its parts
	parts := strings.Split(cpeMatch.Criteria, ":")

	return CPEMatch{
		Criteria:              cpeMatch.Criteria,
		MatchCriteriaID:       cpeMatch.MatchCriteriaID,
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
