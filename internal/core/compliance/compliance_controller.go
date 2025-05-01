package compliance

import (
	"embed"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type httpController struct {
	assetVersionRepository core.AssetVersionRepository
	attestationRepository  core.AttestationRepository
	complianceService      core.ComplianceService
}

type deadSimpleSigningEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewHTTPController(assetVersionRepository core.AssetVersionRepository, attestationRepository core.AttestationRepository, service core.ComplianceService) *httpController {
	return &httpController{
		assetVersionRepository: assetVersionRepository,
		attestationRepository:  attestationRepository,
		complianceService:      service,
	}
}

func ExtractAttestationPayload(content string) (any, error) {
	// check if payload and signature are in content - then it is a dead simple signing envelope - otherwise it is already the payload
	if !strings.Contains(content, "payload") || !strings.Contains(content, "signature") {
		var input any
		if err := json.Unmarshal([]byte(content), &input); err != nil {
			return nil, err
		}
		return input, nil
	}

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

		policy, err := NewPolicy(file.Name(), string(content))
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

func (c *httpController) getAssetVersionCompliance(assetVersion models.AssetVersion) ([]common.PolicyEvaluation, error) {
	// get the attestation
	attestations, err := c.attestationRepository.GetByAssetVersionAndAssetID(assetVersion.AssetID, assetVersion.Name)

	if err != nil {
		return nil, err
	}

	evals, err := c.complianceService.EvalPolicies(attestations)
	return evals, err
}

func (c *httpController) Details(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)

	p := ctx.Param("policy")
	attestations, err := c.attestationRepository.GetByAssetVersionAndAssetID(assetVersion.AssetID, assetVersion.Name)

	if err != nil {
		return ctx.JSON(500, nil)
	}

	for _, policy := range getPolicies() {
		// check if we should have a look at those details
		if strings.TrimSuffix(policy.Filename, ".rego") == p {
			// look for the right attestations
			for _, attestation := range attestations {
				if attestation.AttestationName == policy.AttestationName {
					res := policy.Eval(attestation.Content)
					return ctx.JSON(200, res)
				}

				// we did not find any attestation that matches - lets add the policy with a nil result

			}
		}
	}

	return ctx.NoContent(404)
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

	results := make([][]common.PolicyEvaluation, 0, len(assetVersions))
	for _, assetVersion := range assetVersions {
		compliance, err := c.getAssetVersionCompliance(assetVersion)
		if err != nil {
			return ctx.JSON(500, nil)
		}

		results = append(results, compliance)
	}
	return ctx.JSON(200, results)
}
