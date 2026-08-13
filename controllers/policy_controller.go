package controllers

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type PolicyController struct {
	policyRepository  shared.PolicyRepository
	projectRepository shared.ProjectRepository
}

func NewPolicyController(policyRepository shared.PolicyRepository, projectRepository shared.ProjectRepository) *PolicyController {
	c := &PolicyController{
		policyRepository:  policyRepository,
		projectRepository: projectRepository,
	}

	if err := c.migratePolicies(); err != nil {
		panic(err)
	}
	return c
}

func (c *PolicyController) migratePolicies() error {
	ctx := context.Background()
	// we need to migrate the policies from the old format to the new format
	// this is only needed for the first time we run the application
	// after that we can remove this function
	policies := compliance.GetCommunityManagedPoliciesFromFS()
	policyModels := make([]models.Policy, len(policies))
	for i, policy := range policies {
		policyModels[i] = compliance.ConvertPolicyFsToModel(policy)
	}

	// get all community managed policies from the database
	dbPolicies, err := c.policyRepository.FindCommunityManagedPolicies(ctx, nil)
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
		if err := c.policyRepository.CreateBatch(ctx, nil, toCreate); err != nil {
			return err
		}
	}

	// update the policies
	if len(toUpdate) > 0 {
		if err := c.policyRepository.SaveBatch(ctx, nil, toUpdate); err != nil {
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
				err := c.policyRepository.GetDB(ctx, nil).Model(&p).Association("Projects").Clear()
				if err != nil {
					slog.Warn("failed to clear projects association for policy", "policyID", p.ID, "error", err)
					return
				}
			}(policy)
		}
		wg.Wait()
		if err := c.policyRepository.DeleteBatch(ctx, nil, toDelete); err != nil {
			return err
		}
	}

	return nil
}

// @Summary List organization policies
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Success 200 {array} models.Policy
// @Router /organizations/{organization}/policies [get]
func (c *PolicyController) GetOrganizationPolicies(ctx shared.Context) error {

	org := shared.GetOrg(ctx)
	policies, err := c.policyRepository.FindByOrganizationID(ctx.Request().Context(), nil, org.ID)

	if err != nil {
		return err
	}

	// include the community managed policies
	communityPolicies, err := c.policyRepository.FindCommunityManagedPolicies(ctx.Request().Context(), nil)
	if err != nil {
		return err
	}

	return ctx.JSON(200, append(policies, communityPolicies...))
}

// @Summary List project policies
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Success 200 {array} models.Policy
// @Router /organizations/{organization}/projects/{projectSlug}/policies [get]
func (c *PolicyController) GetProjectPolicies(ctx shared.Context) error {
	project := shared.GetProject(ctx)
	policies, err := c.policyRepository.FindByProjectID(ctx.Request().Context(), nil, project.ID)

	if err != nil {
		return err
	}

	return ctx.JSON(200, policies)
}

// @Summary Get a policy
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param policyID path string true "Policy ID"
// @Success 200 {object} models.Policy
// @Router /organizations/{organization}/policies/{policyID} [get]
func (c *PolicyController) GetPolicy(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	policy, err := c.policyRepository.Read(ctx.Request().Context(), nil, policyUUID)

	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "policy not found")
		}
		return err
	}

	return ctx.JSON(200, policy)
}

// @Summary Create a policy
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param body body dtos.PolicyDTO true "Request body"
// @Success 201 {object} dtos.PolicyDTO
// @Router /organizations/{organization}/policies [post]
func (c *PolicyController) CreatePolicy(ctx shared.Context) error {
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
		OrganizationID: new(org.ID),
		OpaqueID:       nil,
	}

	// create the policy
	if err := c.policyRepository.Create(ctx.Request().Context(), nil, &policyModel); err != nil {
		return err
	}

	return ctx.JSON(201, policy)
}

// @Summary Update a policy
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param policyID path string true "Policy ID"
// @Param body body dtos.PolicyDTO true "Request body"
// @Success 200 {object} models.Policy
// @Router /organizations/{organization}/policies/{policyID} [put]
func (c *PolicyController) UpdatePolicy(ctx shared.Context) error {
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
		OrganizationID: new(org.ID),
	}

	if err := c.policyRepository.Save(ctx.Request().Context(), nil, &policyModel); err != nil {
		return err
	}

	return ctx.JSON(200, policyModel)
}

// @Summary Delete a policy
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param policyID path string true "Policy ID"
// @Success 204
// @Router /organizations/{organization}/policies/{policyID} [delete]
func (c *PolicyController) DeletePolicy(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	// delete the policy
	if err := c.policyRepository.Delete(ctx.Request().Context(), nil, policyUUID); err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "policy not found")
		}
		return err
	}

	return ctx.NoContent(204)
}

// @Summary Enable a policy for a project
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param policyID path string true "Policy ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/policies/{policyID} [put]
func (c *PolicyController) EnablePolicyForProject(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	project := shared.GetProject(ctx)

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	// enable the policy for the project
	if err := c.projectRepository.EnablePolicyForProject(ctx.Request().Context(), nil, project.ID, policyUUID); err != nil {
		return err
	}

	return ctx.NoContent(204)
}

// @Summary Disable a policy for a project
// @Tags Policies
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param policyID path string true "Policy ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/policies/{policyID} [delete]
func (c *PolicyController) DisablePolicyForProject(ctx shared.Context) error {
	policyID := ctx.Param("policyID")

	// parse the uuid
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return err
	}

	project := shared.GetProject(ctx)

	// disable the policy for the project
	if err := c.projectRepository.DisablePolicyForProject(ctx.Request().Context(), nil, project.ID, policyUUID); err != nil {
		return err
	}

	return ctx.NoContent(204)
}
