package compliance_test

import (
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/stretchr/testify/assert"
)

func TestEval(t *testing.T) {
	// load the json from testfiles
	b, err := os.ReadFile("testfiles/build-provenance-input.json")
	if err != nil {
		t.Fatal(err)
	}

	input, err := compliance.ExtractAttestationPayload(string(b))

	if err != nil {
		t.Fatal(err)
	}

	// read the example-policy.rego file
	policyContent, err := os.ReadFile("testfiles/example-policy.rego")
	if err != nil {
		t.Fatal(err)
	}

	// create a new policy
	policy, err := compliance.NewPolicy(string(policyContent))
	if err != nil {
		t.Fatal(err)
	}

	// evaluate the policy
	if res := policy.Eval(input); !*res.Result {
		t.Fatal(err)
	}
}

func TestNewPolicy(t *testing.T) {
	t.Run("should parse the metadata", func(t *testing.T) {
		// read the example-policy.rego file
		policyContent, err := os.ReadFile("testfiles/example-policy.rego")
		if err != nil {
			t.Fatal(err)
		}

		// create a new policy
		policy, err := compliance.NewPolicy(string(policyContent))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "Build from signed source", policy.Title)
		assert.Equal(t, "This policy checks if the build was done from a signed commit. It does not check the signature itself, just that it exists.", policy.Description)
		assert.Equal(t, []string{"iso27001", "A.8 Access Control"}, policy.Tags)

	})
}
