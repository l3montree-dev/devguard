package vulndb

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"golang.org/x/mod/semver"
)

// the osv does contain the debian ecosystem, but it removes all unassigned urgencies
// since there are a lot recent cves unassigned, we decided to mirror the debian security tracker on our own to get the unassigned urgencies as well

type debianSecurityTracker struct {
	httpClient            *http.Client
	affectedCmpRepository core.AffectedComponentRepository
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
type debianJsonResponse = map[string]map[string]debianCVE

func NewDebianSecurityTracker(affectedCmpRepository core.AffectedComponentRepository) debianSecurityTracker {
	return debianSecurityTracker{
		httpClient:            &http.Client{},
		affectedCmpRepository: affectedCmpRepository,
	}
}

var debianBaseUrl = "https://security-tracker.debian.org/tracker/data/json"

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

func (s debianSecurityTracker) fetchAllCVEs() (debianJsonResponse, error) {
	resp, err := s.httpClient.Get(debianBaseUrl)
	if err != nil {
		return debianJsonResponse{}, nil
	}

	defer resp.Body.Close()

	var cves debianJsonResponse
	err = json.NewDecoder(resp.Body).Decode(&cves)
	if err != nil {
		return debianJsonResponse{}, err
	}

	return cves, nil
}

func convertToPurl(packageName string) string {
	return "pkg:deb/debian/" + packageName
}

func debianCveToAffectedComponent(packageName, cveId string, debianCVE debianCVE) []models.AffectedComponent {

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

		for _, version := range cve.Repositories {
			if version == cve.FixedVersion {
				// this debian version is actually not affected.
				continue
			}

			// it is only an affected component, if the version is smaller than the fixed version
			v := normalize.ConvertToSemver(version)
			fixedSemver := normalize.ConvertToSemver(cve.FixedVersion)

			if cve.FixedVersion != "" && semver.Compare("v"+v, "v"+fixedSemver) != -1 {
				continue
			}

			// this version is affected
			affectedComponent := models.AffectedComponent{
				PurlWithoutVersion: purl,
				CVE:                []models.CVE{{CVE: cveId}},
				Ecosystem:          "Debian:" + codenameToVersion[strings.ToLower(debianVersion)],
				Scheme:             "pkg",
				Type:               "deb",
				Name:               packageName,
				Namespace:          utils.Ptr("debian"),
				Qualifiers:         utils.Ptr("arch=source"),
				Source:             "debian-security-tracker",
				Version:            utils.Ptr(version),

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
		for cveId, cve := range packageCves {
			affectedComponents = append(affectedComponents, debianCveToAffectedComponent(packageName, cveId, cve)...)
		}
	}

	err = s.affectedCmpRepository.SaveBatch(nil, affectedComponents)
	if err != nil {
		return err
	}

	return nil
}
