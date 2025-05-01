package compliance_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/utils"
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
	policy, err := compliance.NewPolicy("", string(policyContent))
	if err != nil {
		t.Fatal(err)
	}

	// evaluate the policy
	if res := policy.Eval(input); !*res.Compliant {
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
		policy, err := compliance.NewPolicy("", string(policyContent))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "Build from signed source", policy.Title)
		assert.Equal(t, "This policy checks if the build was done from a signed commit.", policy.Description)
		assert.Equal(t, []string{"iso27001", "A.8 Access Control"}, policy.Tags)

	})
}

func TestOnlyOsiApprovedLicensesPolicy(t *testing.T) {
	sbomContent, err := os.ReadFile("./testfiles/sbom.json")
	if err != nil {
		t.Fatal(err)
	}

	policyContent, err := os.ReadFile("./attestation-compliance-policies/policies/only_osi_approved_licenses.rego")
	if err != nil {
		t.Fatal(err)
	}

	policy, err := compliance.NewPolicy("", string(policyContent))
	if err != nil {
		t.Fatal(err)
	}

	// parse the sbom
	var input any
	err = json.Unmarshal(sbomContent, &input)
	if err != nil {
		t.Fatal(err)
	}

	result := policy.Eval(input)

	expectedResult := &common.PolicyEvaluation{
		PolicyMetadata: policy.PolicyMetadata,
		Compliant:      utils.Ptr(false),
		Violations: []string{
			"Component \"github.com/cloudflare/circl\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/dustin/go-humanize\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/emirpasic/gods\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/go-git/gcfg\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/godbus/dbus/v5\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/golang/groupcache\" has no license declared",
			"Component \"github.com/in-toto/in-toto-golang\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/kevinburke/ssh_config\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/l3montree-dev/devguard\" has no license declared",
			"Component \"github.com/letsencrypt/boulder\" has no license declared",
			"Component \"github.com/opencontainers/go-digest\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/pkg/errors\" uses non-OSI approved license \"non-standard\"",
			"Component \"github.com/pmezard/go-difflib\" uses non-OSI approved license \"non-standard\"",
			"Component \"golang.org/x/crypto\" has no license declared",
			"Component \"golang.org/x/exp\" has no license declared",
			"Component \"golang.org/x/mod\" has no license declared",
			"Component \"golang.org/x/net\" has no license declared",
			"Component \"golang.org/x/oauth2\" has no license declared",
			"Component \"golang.org/x/sync\" has no license declared",
			"Component \"golang.org/x/sys\" has no license declared",
			"Component \"golang.org/x/term\" has no license declared",
			"Component \"golang.org/x/text\" has no license declared",
			"Component \"golang.org/x/time\" has no license declared",
			"Component \"golang.org/x/tools\" has no license declared",
			"Component \"google.golang.org/genproto/googleapis/rpc\" has no license declared",
			"Component \"google.golang.org/protobuf\" has no license declared",
			"Component \"gopkg.in/go-jose/go-jose.v2\" has no license declared",
			"Component \"gopkg.in/warnings.v0\" has no license declared",
			"Component \"gopkg.in/yaml.v3\" has no license declared",
		},
	}

	assert.Equal(t, expectedResult.Compliant, result.Compliant)
	assert.Subset(t, expectedResult.Violations, result.Violations)
	assert.Subset(t, result.Violations, expectedResult.Violations)
}
