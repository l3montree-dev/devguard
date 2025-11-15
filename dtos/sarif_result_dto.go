package dtos

type SarifResult struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Text struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type Rule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	FullDescription  Text   `json:"fullDescription"`
	Help             Text   `json:"help"`
	HelpURI          string `json:"helpURI"`
	ShortDescription Text   `json:"shortDescription"`
	Properties       map[string]any
}

type Driver struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type Region struct {
	StartLine   int  `json:"startLine"`
	StartColumn int  `json:"startColumn"`
	EndLine     int  `json:"endLine"`
	EndColumn   int  `json:"endColumn"`
	Snippet     Text `json:"snippet"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PartialFingerprints struct {
	CommitSha     string `json:"commitSha"`
	Email         string `json:"email"`
	Author        string `json:"author"`
	Date          string `json:"date"`
	CommitMessage string `json:"commitMessage"`
}
type Fingerprints struct {
	MatchBasedID          string `json:"matchBasedId/v1"`
	CalculatedFingerprint string `json:"calculatedFingerprint/v1"`
}

type Properties struct {
	Precision string   `json:"precision"`
	Tags      []string `json:"tags"`
}

type Result struct {
	Kind                string `json:"kind"`
	RuleID              string `json:"ruleId"`
	Message             Text
	Locations           []Location           `json:"locations"`
	Properties          *Properties          `json:"properties,omitempty"`
	Fingerprints        *Fingerprints        `json:"fingerprints,omitempty"`
	PartialFingerprints *PartialFingerprints `json:"partialFingerprints,omitempty"`
}
