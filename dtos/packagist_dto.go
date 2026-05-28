package dtos

import "encoding/json"

type PackagistPackageResponse struct {
	Packages           map[string][]PackagistPackageVersion `json:"packages,omitempty"`
	SecurityAdvisories []PackagistSecurityAdvisory          `json:"security-advisories,omitempty"`
}

type PackagistSecurityAdvisory struct {
	AdvisoryID       string `json:"advisoryId"`
	AffectedVersions string `json:"affectedVersions"`
}

type PackagistPackageVersion struct {
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	Keywords          []string `json:"keywords,omitempty"`
	Homepage          string   `json:"homepage,omitempty"`
	Version           string   `json:"version"`
	VersionNormalized string   `json:"version_normalized,omitempty"`
	License           []string `json:"license,omitempty"`

	Authors []PackagistAuthor `json:"authors,omitempty"`

	Source *PackagistSource `json:"source,omitempty"`
	Dist   *PackagistDist   `json:"dist,omitempty"`

	Type string `json:"type,omitempty"`

	Support *PackagistSupport `json:"support,omitempty"`

	Require    StringMapField `json:"require,omitempty"`
	RequireDev StringMapField `json:"require-dev,omitempty"`

	Suggest  StringMapField `json:"suggest,omitempty"`
	Provide  StringMapField `json:"provide,omitempty"`
	Replace  StringMapField `json:"replace,omitempty"`
	Conflict StringMapField `json:"conflict,omitempty"`

	Time string `json:"time,omitempty"`

	Autoload StringMapField `json:"autoload,omitempty"`

	Extra StringMapField `json:"extra,omitempty"`
}

type PackagistAuthor struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	Role     string `json:"role,omitempty"`
}

type PackagistSource struct {
	Type      string `json:"type,omitempty"`
	URL       string `json:"url,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type PackagistDist struct {
	Type      string `json:"type,omitempty"`
	URL       string `json:"url,omitempty"`
	Reference string `json:"reference,omitempty"`
	Shasum    string `json:"shasum,omitempty"`
}

type PackagistSupport struct {
	Email    string `json:"email,omitempty"`
	Issues   string `json:"issues,omitempty"`
	Forum    string `json:"forum,omitempty"`
	Wiki     string `json:"wiki,omitempty"`
	IRC      string `json:"irc,omitempty"`
	Source   string `json:"source,omitempty"`
	Docs     string `json:"docs,omitempty"`
	RSS      string `json:"rss,omitempty"`
	Chat     string `json:"chat,omitempty"`
	Security string `json:"security,omitempty"`
}


type StringMapField struct {
	Map map[string]any
	Raw any
}

func (s *StringMapField) UnmarshalJSON(b []byte) error {
	// null
	if string(b) == "null" {
		return nil
	}

	// object case
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err == nil {
		s.Map = obj
		s.Raw = obj
		return nil
	}

	// fallback: store raw value
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	s.Raw = raw
	return nil
}
