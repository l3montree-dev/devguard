package dtos

type VulnInPackageDTO struct {
	CVEID        string  `json:"cveId"`
	FixedVersion *string `json:"fixedVersion"`
}

type AffectedComponentDTO struct {
	ID int64 `json:"id"`

	PurlWithoutVersion string `json:"purl"`
	Ecosystem          string `json:"ecosystem"`

	Version           *string `json:"version"`
	SemverIntroduced  *string `json:"semverStart"`
	SemverFixed       *string `json:"semverEnd"`
	VersionIntroduced *string `json:"versionIntroduced"`
	VersionFixed      *string `json:"versionFixed"`

	CVEs []CVEDTO `json:"cves"`
}
