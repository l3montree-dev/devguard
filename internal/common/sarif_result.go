package common

type SarifResult struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Text struct {
	Text string `json:"text"`
}

type Rule struct {
	Id               string `json:"id"`
	Name             string `json:"name"`
	FullDescription  Text   `json:"fullDescription"`
	Help             Text   `json:"help"`
	HelpUri          string `json:"helpUri"`
	ShortDescription Text   `json:"shortDescription"`
}

type Run struct {
	Tool struct {
		Driver struct {
			Name  string `json:"name"`
			Rules []Rule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []Result `json:"results"`
}

type Result struct {
	Kind    string `json:"kind"`
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
