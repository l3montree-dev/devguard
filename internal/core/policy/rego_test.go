package policy_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/policy"
)

func TestEval(t *testing.T) {
	// load the json from testfiles
	b, err := os.ReadFile("testfiles/build-provenance-input.json")
	if err != nil {
		t.Fatal(err)
	}

	// unmarshal the json
	var input map[string]any
	if err := json.Unmarshal(b, &input); err != nil {
		t.Fatal(err)
	}

	// base64 decode the payload
	payload, err := base64.StdEncoding.DecodeString(input["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}

	escapedPayload := strings.ReplaceAll(string(payload), "\n", "\\n")

	// read the example-policy.rego file
	policyContent, err := os.ReadFile("testfiles/example-policy.rego")
	if err != nil {
		t.Fatal(err)
	}

	// create a new policy
	policy, err := policy.NewPolicy("example-policy", string(policyContent))
	if err != nil {
		t.Fatal(err)
	}

	// evaluate the policy
	if err := policy.Eval(escapedPayload); err != nil {
		t.Fatal(err)
	}

	t.Fail()
}
