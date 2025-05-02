package compliance

import (
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
	return &policyController{
		policyRepository:  policyRepository,
		projectRepository: projectRepository,
	}
}

func (c *policyController) GetOrganizationPolicies(ctx core.Context) error {

	org := core.GetOrganization(ctx)
	policies, err := c.policyRepository.FindByOrganizationId(org.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policies)
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

	org := core.GetOrganization(ctx)

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

	org := core.GetOrganization(ctx)

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
