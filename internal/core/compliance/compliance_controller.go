package compliance

import (
	"embed"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type httpController struct {
	policies               []Policy
	assetVersionRepository core.AssetVersionRepository
}

type deadSimpleSigningEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewHTTPController(assetVersionRepository core.AssetVersionRepository) *httpController {
	return &httpController{
		assetVersionRepository: assetVersionRepository,
		policies:               getPolicies(),
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

// embed the policies in the binary
//
//go:embed attestation-compliance-policies/policies/*.rego

var policiesFs embed.FS

func getPolicies() []Policy {
	// fetch all policies
	policyFiles, err := policiesFs.ReadDir("attestation-compliance-policies/policies")
	if err != nil {
		return nil
	}

	var policies []Policy
	for _, file := range policyFiles {
		content, err := policiesFs.ReadFile(filepath.Join("attestation-compliance-policies/policies", file.Name()))
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

// embed the build provenance input in the binary - just until we have attestations ready
//
//go:embed testfiles/build-provenance-input.json
var buildProvenanceInput []byte

func (c *httpController) getAssetVersionCompliance(assetVersion models.AssetVersion) ([]PolicyEvaluation, error) {

	// extract the policy
	input, err := ExtractAttestationPayload(string(buildProvenanceInput))
	if err != nil {
		return nil, err
	}

	results := make([]PolicyEvaluation, 0, len(c.policies))
	for _, policy := range c.policies {
		results = append(results, policy.Eval(input))
	}

	// evaluate the policy
	return results, nil
}

func (c *httpController) AssetCompliance(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	results, err := c.getAssetVersionCompliance(assetVersion)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *httpController) ProjectCompliance(ctx core.Context) error {
	// get all default asset version from the project
	project := core.GetProject(ctx)
	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectID(project.ID)

	if err != nil {
		return ctx.JSON(500, nil)
	}

	results := make([][]PolicyEvaluation, 0, len(assetVersions))
	for _, assetVersion := range assetVersions {
		compliance, err := c.getAssetVersionCompliance(assetVersion)
		if err != nil {
			return ctx.JSON(500, nil)
		}

		results = append(results, compliance)
	}
	return ctx.JSON(200, results)
}
