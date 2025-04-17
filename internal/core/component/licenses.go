package component

import (
	_ "embed"
	"encoding/json"
)

//go:embed licenses.json
var licensesFile []byte

type license struct {
	Reference             *string  `json:"reference"`
	IsDeprecatedLicenseID *bool    `json:"isDeprecatedLicenseId"`
	DetailsURL            *string  `json:"detailsUrl"`
	ReferenceNumber       *int     `json:"referenceNumber"`
	Name                  string   `json:"name"`
	LicenseID             string   `json:"licenseId"`
	SeeAlso               []string `json:"seeAlso"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
}

type licenseJsonFile struct {
	LicenseListVersion string    `json:"licenseListVersion"`
	Licenses           []license `json:"licenses"`
}

var licenseMap map[string]license

func init() {
	licenseMap = make(map[string]license)
	var licenses licenseJsonFile
	if err := json.Unmarshal(licensesFile, &licenses); err != nil {
		panic(err)
	}
	for _, license := range licenses.Licenses {
		licenseMap[license.LicenseID] = license
	}
}
