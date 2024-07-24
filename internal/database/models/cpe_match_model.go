package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type CPEMatch struct {
	MatchCriteriaID string `json:"matchCriteriaId" gorm:"primaryKey;type:text;"`
	Criteria        string `json:"criteria" gorm:"type:text;"`
	Part            string `json:"part" gorm:"index;type:text;"`
	Vendor          string `json:"vendor" gorm:"index;type:text;"`
	Product         string `json:"product" gorm:"index;type:text;"`

	Update    string `json:"update" gorm:"type:text;"`
	Edition   string `json:"edition" gorm:"type:text;"`
	Language  string `json:"language" gorm:"type:text;"`
	SwEdition string `json:"swEdition" gorm:"type:text;"`
	TargetSw  string `json:"targetSw" gorm:"type:text;"`
	TargetHw  string `json:"targetHw" gorm:"type:text;"`
	Other     string `json:"other" gorm:"type:text;"`

	Version string `json:"version" gorm:"index;type:text;"` // if any, should be '*'

	VersionEndExcluding *string `json:"versionEndExcluding" gorm:"index;type:text;"`
	VersionEndIncluding *string `json:"versionEndIncluding" gorm:"index;type:text;"`

	VersionStartIncluding *string `json:"versionStartIncluding" gorm:"index;type:text;"`
	VersionStartExcluding *string `json:"versionStartExcluding" gorm:"index;type:text;"`

	Vulnerable bool `json:"vulnerable" gorm:"type:boolean;"`

	CVEs []*CVE `json:"cve" gorm:"many2many:cve_cpe_match;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// there is no stable id across the nvd and the cvelist project.
// we need to create a stable id for the cpe match
// thus use the criteria to create a stable id by hashing it
func (c *CPEMatch) CalculateHash() string {
	// build the stable map
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%t",
		c.Criteria,
		c.Part,
		c.Vendor,
		c.Product,
		c.Version,
		c.Update,
		c.Edition,
		c.Language,
		c.SwEdition,
		c.TargetSw,
		c.TargetHw,
		c.Other,
		utils.SafeDereference(c.VersionEndExcluding),
		utils.SafeDereference(c.VersionEndIncluding),
		utils.SafeDereference(c.VersionStartIncluding),
		utils.SafeDereference(c.VersionStartExcluding),
		c.Vulnerable,
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])
}

func (c *CPEMatch) BeforeSave(*gorm.DB) error {
	// check if MatchCriteriaID is already set
	if c.MatchCriteriaID != "" {
		return nil
	}
	c.MatchCriteriaID = c.CalculateHash()
	return nil
}
