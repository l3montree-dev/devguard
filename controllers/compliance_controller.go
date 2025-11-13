package controllers

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type complianceController struct {
	assetVersionRepository shared.AssetVersionRepository
	attestationRepository  shared.AttestationRepository
	policyRepository       shared.PolicyRepository
}

type deadSimpleSigningEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func NewComplianceController(assetVersionRepository shared.AssetVersionRepository, attestationRepository shared.AttestationRepository, policyRepository shared.PolicyRepository) *complianceController {
	return &complianceController{
		assetVersionRepository: assetVersionRepository,
		policyRepository:       policyRepository,
		attestationRepository:  attestationRepository,
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

func (c *complianceController) getAssetVersionCompliance(projectID uuid.UUID, assetVersion models.AssetVersion) ([]PolicyEvaluation, error) {
	// get the attestation
	attestations, err := c.attestationRepository.GetByAssetVersionAndAssetID(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return nil, err
	}

	policies, err := c.policyRepository.FindByProjectID(projectID)
	if err != nil {
		return nil, err
	}

	results := make([]PolicyEvaluation, 0, len(policies))
foundMatch:
	for _, policy := range policies {
		// check if we find an attestation that matches
		for _, attestation := range attestations {
			if attestation.PredicateType != policy.PredicateType {
				continue
			}
			res := Eval(policy, attestation.Content)
			// this matches - lets add it
			results = append(results, res)
			continue foundMatch
		}
		// we did not find any attestation that matches - lets add the policy with a nil result
		results = append(results, Eval(policy, nil))
	}

	// evaluate the policy
	return results, nil
}

func (c *complianceController) Details(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	p := ctx.Param("policy")
	// parse the uuid
	policyID, err := uuid.Parse(p)
	if err != nil {
		return ctx.JSON(400, nil)
	}
	// get all policies
	policy, err := c.policyRepository.Read(policyID)
	if err != nil {
		return ctx.JSON(404, nil)
	}

	attestations, err := c.attestationRepository.GetByAssetVersionAndAssetID(assetVersion.AssetID, assetVersion.Name)

	if err != nil {
		return ctx.JSON(500, nil)
	}

	// look for the right attestations
	for _, attestation := range attestations {
		if attestation.PredicateType == policy.PredicateType {
			res := Eval(policy, attestation.Content)
			return ctx.JSON(200, res)
		}
	}
	// we did not find any attestation that matches - lets add the policy with a nil result
	return ctx.JSON(200, Eval(policy, nil))
}

func (c *complianceController) AssetCompliance(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	project := shared.GetProject(ctx)

	results, err := c.getAssetVersionCompliance(project.ID, assetVersion)
	if err != nil {
		return ctx.JSON(500, nil)
	}

	return ctx.JSON(200, results)
}

func (c *complianceController) ProjectCompliance(ctx shared.Context) error {
	// get all default asset version from the project
	project := shared.GetProject(ctx)
	assetVersions, err := c.assetVersionRepository.GetDefaultAssetVersionsByProjectID(project.ID)

	if err != nil {
		return ctx.JSON(500, nil)
	}

	results := make([][]PolicyEvaluation, 0, len(assetVersions))
	for _, assetVersion := range assetVersions {
		compliance, err := c.getAssetVersionCompliance(project.ID, assetVersion)
		if err != nil {
			return ctx.JSON(500, nil)
		}

		results = append(results, compliance)
	}
	return ctx.JSON(200, results)
}
