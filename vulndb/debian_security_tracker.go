package vulndb

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/mod/semver"
	"gorm.io/gorm"
	"pault.ag/go/debian/version"
)

// the osv does contain the debian ecosystem, but it removes all unassigned urgencies
// since there are a lot recent cves unassigned, we decided to mirror the debian security tracker on our own to get the unassigned urgencies as well

type debianSecurityTracker struct {
	httpClient            *http.Client
	affectedCmpRepository shared.AffectedComponentRepository
}

/*
*

	"releases": {
		"bookworm": {
			"status": "resolved",
			"repositories": {
				"bookworm": "3.0.13-1~deb12u1",
				"bookworm-security": "3.0.11-1~deb12u2"
			},
			"fixed_version": "3.0.13-1~deb12u1",
			"urgency": "not yet assigned"
		},
		"bullseye": {
			"status": "open",
			"repositories": {
				"bullseye": "1.1.1w-0+deb11u1",
				"bullseye-security": "1.1.1n-0+deb11u5"
			},
			"urgency": "not yet assigned",
			"nodsa": "Minor issue",
			"nodsa_reason": ""
		},
	}

*
*/
type debianCveRelease struct {
	Status       string            `json:"status"`
	Repositories map[string]string // the value is important. It does contain the versions installed in every release. - if the status is resolved, a fixed version key is present.
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

type debianCVE struct {
	Description string                      `json:"description"`
	Debianbug   int                         `json:"debianbug"`
	Scope       string                      `json:"scope"`
	Releases    map[string]debianCveRelease `json:"releases"`
}

// first key is the package name
// second key is the cve id
// value is the cve
type debianJSONResponse = map[string]map[string]debianCVE

func NewDebianSecurityTracker(affectedCmpRepository shared.AffectedComponentRepository) debianSecurityTracker {
	return debianSecurityTracker{
		httpClient:            &http.Client{},
		affectedCmpRepository: affectedCmpRepository,
	}
}

var debianBaseURL = "https://security-tracker.debian.org/tracker/data/json"

var codenameToVersion = map[string]string{
	"buzz":     "1.1",
	"rex":      "1.2",
	"bo":       "1.3",
	"hamm":     "2.0",
	"slink":    "2.1",
	"potato":   "2.2",
	"woody":    "3",
	"sarge":    "3.1",
	"etch":     "4",
	"lenny":    "5",
	"squeeze":  "6",
	"wheezy":   "7",
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
}

func (s debianSecurityTracker) fetchAllCVEs() (debianJSONResponse, error) {
	resp, err := s.httpClient.Get(debianBaseURL)
	if err != nil {
		return debianJSONResponse{}, nil
	}

	defer resp.Body.Close()

	var cves debianJSONResponse
	err = json.NewDecoder(resp.Body).Decode(&cves)
	if err != nil {
		return debianJSONResponse{}, err
	}

	return cves, nil
}

func convertToPurl(packageName string) string {
	return "pkg:deb/debian/" + packageName
}

func debianCveToAffectedComponent(packageName, cveID string, debianCVE debianCVE) []models.AffectedComponent {

	affectedComponents := make([]models.AffectedComponent, 0)

	for debianVersion, cve := range debianCVE.Releases {
		if _, ok := codenameToVersion[strings.ToLower(debianVersion)]; !ok {
			// we do not support this debian version
			continue
		}

		if cve.Urgency == "unimportant" {
			// this cve is unimportant
			continue
		}

		purl := convertToPurl(packageName)
		// convert the fixedVersion to semver - this makes it possible to compare the versions
		fixed, err := version.Parse(cve.FixedVersion)
		fixedVersionExists := true
		if err != nil {
			fixedVersionExists = false
		}

		for _, v := range cve.Repositories {
			currentVersion, err := version.Parse(v)
			if err != nil {
				continue
			}
			// skip if current version is greater than or equal to the fixed version
			// (only versions strictly smaller than the fixed version are affected)
			if fixedVersionExists && version.Compare(fixed, currentVersion) < 0 {
				// this version is not affected
				continue
			}

			// it is only an affected component, if the version is smaller than the fixed version
			v, _ := normalize.ConvertToSemver(v)
			fixedSemver, _ := normalize.ConvertToSemver(cve.FixedVersion)

			if cve.FixedVersion != "" && semver.Compare("v"+v, "v"+fixedSemver) != -1 {
				continue
			}

			// this version is affected
			affectedComponent := models.AffectedComponent{
				PurlWithoutVersion: purl,
				CVE:                []models.CVE{{CVE: cveID}},
				Ecosystem:          "Debian:" + codenameToVersion[strings.ToLower(debianVersion)],
				Scheme:             "pkg",
				Type:               "deb",
				Name:               packageName,
				Namespace:          utils.Ptr("debian"),
				Qualifiers:         databasetypes.JSONB{"arch": "source"},
				Source:             "debian-security-tracker",
				Version:            utils.Ptr(v),
				// we just fake a semver version here
				// SemverFixed: utils.EmptyThenNil(normalize.ConvertToSemver(fixedSemver)),
				VersionFixed: utils.EmptyThenNil(cve.FixedVersion),
			}

			affectedComponents = append(affectedComponents, affectedComponent)
		}
	}

	// unique by hash
	return utils.UniqBy(affectedComponents, func(a models.AffectedComponent) string {
		return a.CalculateHash()
	})
}

func (s debianSecurityTracker) Mirror() error {
	cves, err := s.fetchAllCVEs()
	if err != nil {
		return err
	}

	affectedComponents := make([]models.AffectedComponent, 0)
	for packageName, packageCves := range cves {
		for cveID, cve := range packageCves {
			affectedComponents = append(affectedComponents, debianCveToAffectedComponent(packageName, cveID, cve)...)
		}
	}

	err = s.affectedCmpRepository.GetDB(nil).Transaction(func(tx *gorm.DB) error {
		// remove all dsa affected components first
		err = tx.Where("source = ?", "debian-security-tracker").Delete(&models.AffectedComponent{}).Error
		if err != nil {
			return err
		}

		return s.affectedCmpRepository.SaveBatch(tx, affectedComponents)
	})

	if err != nil {
		return err
	}

	return nil
}
