package compliance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
)

type httpController struct{}

type deadSimpleSigningEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewController() *httpController {
	return &httpController{}
}

func ExtractPolicy(content string) (any, error) {
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

type complianceEvaluationDTO struct {
	Name        string                `json:"name"`
	Evaluations []policyEvaluationDTO `json:"evaluations"`
}

type policyEvaluationDTO struct {
	Compliant bool   `json:"compliant"`
	Message   string `json:"message"`
}

func (c *httpController) Compliance(ctx core.Context) error {
	// fetch the policy
	content, err := os.ReadFile("testfiles/example-policy.rego")
	if err != nil {
		return err
	}

	policy, err := NewPolicy(string(content))
	if err != nil {
		return err
	}

	// get all attestations of the asset
	attestations, err := os.ReadFile("testfiles/build-provenance-input.json")
	if err != nil {
		return err
	}

	// extract the policy
	input, err := ExtractPolicy(string(attestations))
	if err != nil {
		return err
	}

	// evaluate the policy
	if err := policy.Eval(input); err != nil {
	}

	return nil
}
