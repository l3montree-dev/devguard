package licenses

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	"github.com/package-url/packageurl-go"
)

//go:embed approved-licenses.json
var licensesFile []byte

type License struct {
	Reference             *string  `json:"reference"`
	IsDeprecatedLicenseID *bool    `json:"isDeprecatedLicenseId"`
	DetailsURL            *string  `json:"detailsURL"`
	ReferenceNumber       *int     `json:"referenceNumber"`
	Name                  string   `json:"name"`
	LicenseID             string   `json:"licenseId"`
	SeeAlso               []string `json:"seeAlso"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
}

type LicenseJSONFile struct {
	LicenseListVersion string    `json:"licenseListVersion"`
	Licenses           []License `json:"licenses"`
}

var LicenseMap map[string]License

func init() {
	LicenseMap = make(map[string]License)
	var licenses LicenseJSONFile
	if err := json.Unmarshal(licensesFile, &licenses); err != nil {
		panic(err)
	}
	for _, license := range licenses.Licenses {
		LicenseMap[strings.ToLower(license.LicenseID)] = license
	}
	if err := loadLicensesIntoMemory(); err != nil {
		panic(err)
	}
}

//go:embed alpine-licenses.json
var alpineLicenses []byte
var alpineLicenseMap map[string]string = make(map[string]string, 100*1000)
var alpineMutex sync.Mutex

// some components have a already modified purl to improve cve -> purl matching (see cdx bom normalization)
// we basically need to revert that for license matching - thus the second parameter
// see pkg:deb/debian/gdbm@1.23 as an example. Fallback version is 1.23-3
func GetAlpineLicense(pURL packageurl.PackageURL) string {
	var err error
	var license string
	alpineMutex.Lock()
	if len(alpineLicenseMap) == 0 {
		err = json.Unmarshal(alpineLicenses, &alpineLicenseMap)
		if err != nil {
			alpineMutex.Unlock()
			return license
		}
	}
	alpineMutex.Unlock()
	license, exists := alpineLicenseMap[pURL.Name+pURL.Version]
	if exists {
		return license
	}
	return ""
}

func loadLicensesIntoMemory() error {
	alpineMutex.Lock()
	err := json.Unmarshal(alpineLicenses, &alpineLicenseMap)
	alpineMutex.Unlock()
	if err != nil {
		return err
	}
	debianMutex.Lock()
	err = json.Unmarshal(debianLicenses, &debianLicenseMap)
	debianMutex.Unlock()
	return err
}

//go:embed debian-licenses.json
var debianLicenses []byte
var debianLicenseMap map[string]string = make(map[string]string, 100*1000)
var debianMutex sync.Mutex

// some components have a already modified purl to improve cve -> purl matching (see cdx bom normalization)
// we basically need to revert that for license matching - thus the second parameter
// see pkg:deb/debian/gdbm@1.23 as an example. Fallback version is 1.23-3
func GetDebianLicense(pURL packageurl.PackageURL) string {
	var err error
	var license string
	debianMutex.Lock()
	if len(debianLicenseMap) == 0 {
		err = json.Unmarshal(debianLicenses, &debianLicenseMap)
		if err != nil {
			debianMutex.Unlock()
			return license
		}
	}
	debianMutex.Unlock()
	license, exists := debianLicenseMap[pURL.Name+pURL.Version]
	if exists {
		return license
	}
	return ""
}
