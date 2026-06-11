package compliance

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestEval(t *testing.T) {
	// load the json from testfiles
	b, err := os.ReadFile("testfiles/build-provenance-input.json")
	if err != nil {
		t.Fatal(err)
	}

	input, err := utils.ExtractAttestationPayload(string(b))

	if err != nil {
		t.Fatal(err)
	}

	// read the example-policy.rego file
	policyContent, err := os.ReadFile("testfiles/example-policy.rego")
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := parseMetadata("", string(policyContent))
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{PolicyMetadata: metadata, Content: string(policyContent)}

	// evaluate the policy
	res := Eval(policy, input)
	if res.Compliant == nil || *res.Compliant != true {
		t.Fatal(res)
	}
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

	metadata, err := parseMetadata("", string(policyContent))
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{PolicyMetadata: metadata, Content: string(policyContent)}

	// parse the sbom
	var input any
	err = json.Unmarshal(sbomContent, &input)
	if err != nil {
		t.Fatal(err)
	}

	result := Eval(policy, input)

	expectedResult := &PolicyEvaluation{
		Compliant: utils.Ptr(false),
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

func resultKey(r sarif.Result) string {
	return string(r.Kind) + "|" + r.Message.Text
}

func hasDuplicateResults(results []sarif.Result) bool {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		k := resultKey(r)
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

func makeEvaluations(policy Policy, evals []PolicyEvaluation) []PolicyEvaluation {
	for i := range evals {
		evals[i].PolicyID = policy.Filename
		evals[i].PolicyTitle = policy.Title
		evals[i].PolicyDescription = policy.Description
		evals[i].PolicyTags = policy.Tags
	}
	return evals
}

func TestBuildSarifFromPoliciesEvaluations_NoDuplicateResults(t *testing.T) {
	policy := Policy{
		PolicyMetadata: PolicyMetadata{
			Filename:    "test-policy.rego",
			Title:       "Test Policy",
			Description: "A test policy",
			Tags:        []string{"test"},
		},
	}

	t.Run("duplicate violations across evaluations produce no duplicates", func(t *testing.T) {
		compliant := false
		evaluations := makeEvaluations(policy, []PolicyEvaluation{
			{Compliant: &compliant, Violations: []string{"missing signature", "untrusted source"}},
			{Compliant: &compliant, Violations: []string{"missing signature", "untrusted source"}},
		})
		results := BuildSarifFromPoliciesEvaluations("registry.example.com/image:latest", evaluations).Runs[0].Results
		if hasDuplicateResults(results) {
			t.Errorf("BuildSarifFromPoliciesEvaluations returned duplicate result entries: %v", results)
		}
	})

	t.Run("same violation repeated within one evaluation produces no duplicates", func(t *testing.T) {
		compliant := false
		evaluations := makeEvaluations(policy, []PolicyEvaluation{
			{Compliant: &compliant, Violations: []string{"missing signature", "missing signature"}},
		})
		results := BuildSarifFromPoliciesEvaluations("registry.example.com/image:latest", evaluations).Runs[0].Results
		if hasDuplicateResults(results) {
			t.Errorf("BuildSarifFromPoliciesEvaluations returned duplicate result entries: %v", results)
		}
	})

	t.Run("multiple compliant evaluations produce no duplicate pass results", func(t *testing.T) {
		compliant := true
		evaluations := makeEvaluations(policy, []PolicyEvaluation{
			{Compliant: &compliant},
			{Compliant: &compliant},
			{Compliant: &compliant},
		})
		results := BuildSarifFromPoliciesEvaluations("registry.example.com/image:latest", evaluations).Runs[0].Results
		if hasDuplicateResults(results) {
			t.Errorf("BuildSarifFromPoliciesEvaluations returned duplicate pass result entries: %v", results)
		}
	})

	t.Run("mix of compliant and non-compliant evaluations with overlapping violations", func(t *testing.T) {
		compliant := true
		notCompliant := false
		evaluations := makeEvaluations(policy, []PolicyEvaluation{
			{Compliant: &compliant},
			{Compliant: &notCompliant, Violations: []string{"missing signature"}},
			{Compliant: &notCompliant, Violations: []string{"missing signature"}},
			{Compliant: &compliant},
		})
		results := BuildSarifFromPoliciesEvaluations("registry.example.com/image:latest", evaluations).Runs[0].Results
		if hasDuplicateResults(results) {
			t.Errorf("BuildSarifFromPoliciesEvaluations returned duplicate result entries: %v", results)
		}
	})

	t.Run("single evaluation with no violations produces no results", func(t *testing.T) {
		evaluations := makeEvaluations(policy, []PolicyEvaluation{
			{Compliant: utils.Ptr(true)},
		})
		results := BuildSarifFromPoliciesEvaluations("registry.example.com/image:latest", evaluations).Runs[0].Results
		if hasDuplicateResults(results) {
			t.Errorf("BuildSarifFromPoliciesEvaluations returned duplicate result entries: %v", results)
		}
	})
}
