package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v2"
)

type PolicyMetadata struct {
	Title            string   `yaml:"title"`
	Description      string   `yaml:"description"`
	Tags             []string `yaml:"tags"`
	RelatedResources []string `yaml:"relatedResources"`
}
type Policy struct {
	PolicyMetadata
	Content string
	query   rego.PreparedEvalQuery
}

type PolicyEvaluation struct {
	PolicyMetadata
	Result *bool
}

var packageRegexp = regexp.MustCompile(`(?m)^package compliance`)
var metadataRegexp = regexp.MustCompile(`^\s*#\s*METADATA`)

func parseMetadata(content string) (PolicyMetadata, error) {
	// split the content by first occurence of a line, that starts with "package compliance"
	parts := packageRegexp.Split(content, 2)

	// do a sanity check. It should start with "METADATA"
	if len(parts) < 2 {
		return PolicyMetadata{}, fmt.Errorf("metadata not found")
	}

	yamlData := parts[0]
	if yamlData == "" {
		return PolicyMetadata{}, nil
	}

	yamlLines := strings.Split(yamlData, "\n")
	// remove everything including metadata line
	collectedLines := []string{}
	collect := false
	for _, line := range yamlLines {
		if metadataRegexp.MatchString(line) {
			collect = true
			continue
		}

		if collect {
			// remove leading comment indicators
			collectedLines = append(collectedLines, strings.TrimPrefix(line, "#"))
		}
	}

	// join the lines and unmarshal the yaml
	yamlData = strings.Join(collectedLines, "\n")
	var metadata PolicyMetadata
	if err := yaml.Unmarshal([]byte(yamlData), &metadata); err != nil {
		return PolicyMetadata{}, err
	}

	return metadata, nil
}

func NewPolicy(content string) (*Policy, error) {
	r := rego.New(
		rego.Query("data.compliance.allow"),
		rego.Module("", content),
	)

	ctx := context.TODO()
	query, err := r.PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	metadata, err := parseMetadata(content)
	if err != nil {
		return nil, err
	}

	return &Policy{
		PolicyMetadata: metadata,
		Content:        content,
		query:          query,
	}, nil
}

func (p *Policy) Eval(input any) PolicyEvaluation {
	rs, err := p.query.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		return PolicyEvaluation{
			PolicyMetadata: p.PolicyMetadata,
			Result:         nil,
		}
	}

	result := rs.Allowed()
	return PolicyEvaluation{
		PolicyMetadata: p.PolicyMetadata,
		Result:         &result,
	}
}
