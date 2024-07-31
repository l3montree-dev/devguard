package vulndb

import "net/http"

// the osv does contain the debian ecosystem, but it removes all unassigned urgencies
// since there are a lot recent cves unassigned, we decided to mirror the debian security tracker on our own to get the unassigned urgencies as well

type debianSecurityTracker struct {
	httpClient *http.Client
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

func NewDebianSecurityTracker() debianSecurityTracker {
	return debianSecurityTracker{
		httpClient: &http.Client{},
	}
}

var debianBaseUrl = "https://security-tracker.debian.org/tracker/data/json"

func fetchAllCVEs() {

}
