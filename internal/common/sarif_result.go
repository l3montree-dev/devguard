package common

type SarifResult struct {
	Runs []Run `json:"runs"`
}

type Run struct {
	Tool struct {
		Driver struct {
			Name string `json:"name"`
		} `json:"driver"`
	} `json:"tool"`
	Results []Result `json:"results"`
}

type Result struct {
	RuleId  string `json:"ruleId"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				Uri       string `json:"uri"`
				UriBaseId string `json:"uriBaseId"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
				Snippet     struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Properties struct {
		Precision string   `json:"precision"`
		Tags      []string `json:"tags"`
	} `json:"properties"`
	Fingerprints struct {
		MatchBasedId string `json:"matchBasedId/v1"`
	} `json:"fingerprints"`
	PartialFingerprints struct {
		CommitSha     string `json:"commitSha"`
		Email         string `json:"email"`
		Author        string `json:"author"`
		Date          string `json:"date"`
		CommitMessage string `json:"commitMessage"`
	} `json:"partialFingerprints"`
}
