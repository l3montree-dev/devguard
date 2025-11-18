package dtos

import "time"

type OpenSourceInsightsVersionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt  time.Time `json:"publishedAt"`
	IsDefault    bool      `json:"isDefault"`
	Licenses     []string  `json:"licenses"`
	AdvisoryKeys []any     `json:"advisoryKeys"`
	Links        []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	SlsaProvenances []any    `json:"slsaProvenances"`
	Attestations    []any    `json:"attestations"`
	Registries      []string `json:"registries"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationProvenance string `json:"relationProvenance"`
		RelationType       string `json:"relationType"`
	} `json:"relatedProjects"`
}

type OpenSourceInsightsProjectResponse struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	OpenIssuesCount int        `json:"openIssuesCount"`
	StarsCount      int        `json:"starsCount"`
	ForksCount      int        `json:"forksCount"`
	License         string     `json:"license"`
	Description     string     `json:"description"`
	Homepage        string     `json:"homepage"`
	Scorecard       *Scorecard `json:"scorecard"`
}

type Scorecard struct {
	Date       time.Time `json:"date"`
	Repository struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repository"`
	Scorecard struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"scorecard"`
	Checks []struct {
		Name          string `json:"name"`
		Documentation struct {
			ShortDescription string `json:"shortDescription"`
			URL              string `json:"url"`
		} `json:"documentation"`
		Score   int    `json:"score"`
		Reason  string `json:"reason"`
		Details []any  `json:"details"`
	} `json:"checks"`
	OverallScore float64 `json:"overallScore"`
	Metadata     []any   `json:"metadata"`
}
