package controllers

import (
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type policyController struct {
	policyRepository  shared.PolicyRepository
	projectRepository shared.ProjectRepository
}

func NewPolicyController(policyRepository shared.PolicyRepository, projectRepository shared.ProjectRepository) *policyController {
	c := &policyController{
		policyRepository:  policyRepository,
		projectRepository: projectRepository,
	}

	if err := c.migratePolicies(); err != nil {
		panic(err)
	}
	return c
}

func (c *policyController) migratePolicies() error {
	// we need to migrate the policies from the old format to the new format
	// this is only needed for the first time we run the application
	// after that we can remove this function
	policies := compliance.GetCommunityManagedPoliciesFromFS()
	policyModels := make([]models.Policy, len(policies))
	for i, policy := range policies {
		policyModels[i] = compliance.ConvertPolicyFsToModel(policy)
	}

	// get all community managed policies from the database
	dbPolicies, err := c.policyRepository.FindCommunityManagedPolicies()
	if err != nil {
		return err
	}

	// compare the policies
	comp := utils.CompareSlices(policyModels, dbPolicies, func(p models.Policy) string {
		return *p.OpaqueID
	})

	toCreate := comp.OnlyInA
	toUpdate := comp.InBothB // use the B elements - those are the new policies read from disk
	toDelete := comp.OnlyInB

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
		wg := sync.WaitGroup{}
		for _, policy := range toDelete {
			wg.Add(1)
			go func(p models.Policy) {
				defer wg.Done()
				err := c.policyRepository.GetDB(nil).Model(&p).Association("Projects").Clear()
				if err != nil {
					slog.Warn("failed to clear projects association for policy", "policyID", p.ID, "error", err)
					return
				}
			}(policy)
		}
		wg.Wait()
		if err := c.policyRepository.DeleteBatch(nil, toDelete); err != nil {
			return err
		}
	}

	return nil
}

func (c *policyController) GetOrganizationPolicies(ctx shared.Context) error {

	org := shared.GetOrg(ctx)
	policies, err := c.policyRepository.FindByOrganizationID(org.ID)

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

func (c *policyController) GetProjectPolicies(ctx shared.Context) error {
	project := shared.GetProject(ctx)
	policies, err := c.policyRepository.FindByProjectID(project.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policies)
}

func (c *policyController) GetPolicy(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	policy, err := c.policyRepository.Read(policyUUID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policy)
}

func (c *policyController) CreatePolicy(ctx shared.Context) error {
	policy := dtos.PolicyDTO{}
	if err := ctx.Bind(&policy); err != nil {
		return err
	}

	org := shared.GetOrg(ctx)

	// create a new policy model
	policyModel := models.Policy{
		Rego:           policy.Rego,
		Description:    policy.Description,
		Title:          policy.Title,
		PredicateType:  policy.PredicateType,
		OrganizationID: utils.Ptr(org.ID),
		OpaqueID:       nil,
	}

	// create the policy
	if err := c.policyRepository.Create(nil, &policyModel); err != nil {
		return err
	}

	return ctx.JSON(201, policy)
}

func (c *policyController) UpdatePolicy(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	policy := dtos.PolicyDTO{}
	if err := ctx.Bind(&policy); err != nil {
		return err
	}

	org := shared.GetOrg(ctx)

	// create a new policy model
	policyModel := models.Policy{
		ID:             policyUUID,
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

func (c *policyController) DeletePolicy(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	// delete the policy
	if err := c.policyRepository.Delete(nil, policyUUID); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

func (c *policyController) EnablePolicyForProject(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	project := shared.GetProject(ctx)

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	// enable the policy for the project
	if err := c.projectRepository.EnablePolicyForProject(nil, project.ID, policyUUID); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

func (c *policyController) DisablePolicyForProject(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	project := shared.GetProject(ctx)

	// disable the policy for the project
	if err := c.projectRepository.DisablePolicyForProject(nil, project.ID, policyUUID); err != nil {
		return err
	}

	return ctx.NoContent(204)
}
