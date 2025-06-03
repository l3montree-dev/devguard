package compliance

import (
	"embed"
	"path/filepath"
	"sort"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type policyController struct {
	policyRepository  core.PolicyRepository
	projectRepository core.ProjectRepository
}

func NewPolicyController(policyRepository core.PolicyRepository, projectRepository core.ProjectRepository) *policyController {
	c := &policyController{
		policyRepository:  policyRepository,
		projectRepository: projectRepository,
	}

	if err := c.migratePolicies(); err != nil {
		panic(err)
	}
	return c
}

func convertPolicyFsToModel(policy PolicyFS) models.Policy {
	return models.Policy{
		Rego:           policy.Content,
		Description:    policy.Description,
		Title:          policy.Title,
		PredicateType:  policy.PredicateType,
		OpaqueID:       policy.Filename,
		OrganizationID: nil,
	}
}

func (c *policyController) migratePolicies() error {
	// we need to migrate the policies from the old format to the new format
	// this is only needed for the first time we run the application
	// after that we can remove this function
	policies := getCommunityManagedPoliciesFromFS()
	policyModels := make([]models.Policy, len(policies))
	for i, policy := range policies {
		policyModels[i] = convertPolicyFsToModel(policy)
	}

	// get all community managed policies from the database
	dbPolicies, err := c.policyRepository.FindCommunityManagedPolicies()
	if err != nil {
		return err
	}

	// compare the policies
	comp := utils.CompareSlices(dbPolicies, policyModels, func(p models.Policy) string {
		return p.OpaqueID
	})

	toCreate := comp.OnlyInB
	toUpdate := comp.InBothB // use the B elements - those are the new policies read from disk
	toDelete := comp.OnlyInA

	// set the id for the policies to update
	for i := range toUpdate {
		for j := range dbPolicies {
			if dbPolicies[j].OpaqueID == toUpdate[i].OpaqueID {
				toUpdate[i].ID = dbPolicies[j].ID
				break
			}
		}
	}

	// create the policies
	if len(toCreate) > 0 {
		if err := c.policyRepository.CreateBatch(nil, toCreate); err != nil {
			return err
		}
	}

	// update the policies
	if len(toUpdate) > 0 {
		if err := c.policyRepository.SaveBatch(nil, toUpdate); err != nil {
			return err
		}
	}

	// delete the policies
	if len(toDelete) > 0 {
		if err := c.policyRepository.DeleteBatch(nil, toDelete); err != nil {
			return err
		}
	}

	return nil
}

func (c *policyController) GetOrganizationPolicies(ctx core.Context) error {

	org := core.GetOrg(ctx)
	policies, err := c.policyRepository.FindByOrganizationId(org.ID)

	if err != nil {
		return err
	}

	// include the community managed policies
	communityPolicies, err := c.policyRepository.FindCommunityManagedPolicies()
	if err != nil {
		return err
	}

	return ctx.JSON(200, append(policies, communityPolicies...))
}

func (c *policyController) GetProjectPolicies(ctx core.Context) error {
	project := core.GetProject(ctx)
	policies, err := c.policyRepository.FindByProjectId(project.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policies)
}

func (c *policyController) GetPolicy(ctx core.Context) error {
	policyId := ctx.Param("policyId")

	// parse the uuid
	policyUuid, err := uuid.Parse(policyId)
	if err != nil {
		return err
	}

	policy, err := c.policyRepository.Read(policyUuid)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policy)
}

func (c *policyController) CreatePolicy(ctx core.Context) error {
	policy := policyDTO{}
	if err := ctx.Bind(&policy); err != nil {
		return err
	}

	org := core.GetOrg(ctx)

	// create a new policy model
	policyModel := models.Policy{
		Rego:           policy.Rego,
		Description:    policy.Description,
		Title:          policy.Title,
		PredicateType:  policy.PredicateType,
		OrganizationID: utils.Ptr(org.ID),
	}

	// create the policy
	if err := c.policyRepository.Create(nil, &policyModel); err != nil {
		return err
	}

	return ctx.JSON(201, policy)
}

func (c *policyController) UpdatePolicy(ctx core.Context) error {
	policyId := ctx.Param("policyId")

	// parse the uuid
	policyUuid, err := uuid.Parse(policyId)
	if err != nil {
		return err
	}

	policy := policyDTO{}
	if err := ctx.Bind(&policy); err != nil {
		return err
	}

	org := core.GetOrg(ctx)

	// create a new policy model
	policyModel := models.Policy{
		ID:             policyUuid,
		Rego:           policy.Rego,
		Description:    policy.Description,
		Title:          policy.Title,
		PredicateType:  policy.PredicateType,
		OrganizationID: utils.Ptr(org.ID),
	}

	if err := c.policyRepository.Save(nil, &policyModel); err != nil {
		return err
	}

	return ctx.JSON(200, policyModel)
}

func (c *policyController) DeletePolicy(ctx core.Context) error {
	policyId := ctx.Param("policyId")

	// parse the uuid
	policyUuid, err := uuid.Parse(policyId)
	if err != nil {
		return err
	}

	// delete the policy
	if err := c.policyRepository.Delete(nil, policyUuid); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

func (c *policyController) EnablePolicyForProject(ctx core.Context) error {
	policyId := ctx.Param("policyId")

	project := core.GetProject(ctx)

	// parse the uuid
	policyUuid, err := uuid.Parse(policyId)
	if err != nil {
		return err
	}

	// enable the policy for the project
	if err := c.projectRepository.EnablePolicyForProject(nil, project.ID, policyUuid); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

func (c *policyController) DisablePolicyForProject(ctx core.Context) error {
	policyId := ctx.Param("policyId")

	// parse the uuid
	policyUuid, err := uuid.Parse(policyId)
	if err != nil {
		return err
	}

	project := core.GetProject(ctx)

	// disable the policy for the project
	if err := c.projectRepository.DisablePolicyForProject(nil, project.ID, policyUuid); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

// embed the policies in the binary
//
//go:embed attestation-compliance-policies/policies/*.rego
var policiesFs embed.FS

func getCommunityManagedPoliciesFromFS() []PolicyFS {
	// fetch all policies
	policyFiles, err := policiesFs.ReadDir("attestation-compliance-policies/policies")
	if err != nil {
		return nil
	}

	var policies []PolicyFS
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
