package compliance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
)

type httpController struct {
	policies []Policy
}

type deadSimpleSigningEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewHTTPController() *httpController {
	return &httpController{
		policies: getPolicies(),
	}
}

func ExtractAttestationPayload(content string) (any, error) {
	var envelope deadSimpleSigningEnvelope
	if err := json.Unmarshal([]byte(content), &envelope); err != nil {
		return nil, err
	}

	// decode the payload string from base64
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}

	escapedPayload := strings.ReplaceAll(string(payload), "\n", "\\n")

	// unmarshal the payload
	var input any
	if err := json.Unmarshal([]byte(escapedPayload), &input); err != nil {
		return nil, err
	}

	return input, nil
}

func getPolicies() []Policy {
	path, _ := filepath.Abs("./policies/policies")
	// fetch all policies
	policyFiles, err := os.ReadDir(path)
	if err != nil {
		return nil
	}

	var policies []Policy
	for _, file := range policyFiles {
		content, err := os.ReadFile(filepath.Join(path, file.Name()))
		if err != nil {
			continue
		}

		policy, err := NewPolicy(string(content))
		if err != nil {
			continue
		}

		policies = append(policies, *policy)
	}

	// sort the policies by priority - use a stable sort
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})

	return policies
}

func (c *httpController) Compliance(ctx core.Context) error {
	// get all attestations of the asset
	path, _ := filepath.Abs("./internal/core/compliance/testfiles/build-provenance-input.json")
	attestations, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// extract the policy
	input, err := ExtractAttestationPayload(string(attestations))
	if err != nil {
		return err
	}

	results := make([]PolicyEvaluation, 0, len(c.policies))
	for _, policy := range c.policies {
		results = append(results, policy.Eval(input))
	}

	// evaluate the policy
	return ctx.JSON(200, results)
}
