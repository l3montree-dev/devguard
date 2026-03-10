package dtos

type VulnInPackageDTO struct {
	CVEID        string  `json:"cveId"`
	FixedVersion *string `json:"fixedVersion"`
}

type AffectedComponentDTO struct {
	ID                 string   `json:"id"`
	Source             string   `json:"source"`
	PurlWithoutVersion string   `json:"purl"`
	Ecosystem          string   `json:"ecosystem"`
	Scheme             string   `json:"scheme"`
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	Namespace          *string  `json:"namespace"`
	Version            *string  `json:"version"`
	SemverIntroduced   *string  `json:"semverStart"`
	SemverFixed        *string  `json:"semverEnd"`
	VersionIntroduced  *string  `json:"versionIntroduced"`
	VersionFixed       *string  `json:"versionFixed"`
	CVEs               []CVEDTO `json:"cves"`
}
