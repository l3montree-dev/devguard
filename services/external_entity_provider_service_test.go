package services

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func TestTriggerSync(t *testing.T) {
	tests := []struct {
		name           string
		isExternalOrg  bool
		refreshError   error
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "successful sync",
			isExternalOrg:  true,
			refreshError:   nil,
			expectedStatus: 204,
			expectedError:  false,
		},
		{
			name:           "refresh fails",
			isExternalOrg:  true,
			refreshError:   errors.New("refresh failed"),
			expectedStatus: 500,
			expectedError:  true,
		},
		{
			name:           "not external org",
			isExternalOrg:  false,
			expectedStatus: 400,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			projectService := mocks.NewProjectService(t)
			assetService := mocks.NewAssetService(t)
			assetRepo := mocks.NewAssetRepository(t)
			projectRepo := mocks.NewProjectRepository(t)
			rbacProvider := mocks.NewRBACProvider(t)
			orgRepo := mocks.NewOrganizationRepository(t)
			service := NewExternalEntityProviderService(projectService, assetService, assetRepo, projectRepo, rbacProvider, orgRepo)

			// Create echo context
			e := echo.New()
			req := httptest.NewRequest("POST", "/sync", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Setup org
			org := models.Org{
				Model: models.Model{ID: uuid.New()},
			}
			if tt.isExternalOrg {
				org.ExternalEntityProviderID = utils.Ptr("gitlab")
			}

			// Setup session
			session := mocks.NewAuthSession(t)
			if tt.isExternalOrg {
				session.On("GetUserID").Return("user123")
			}

			// Setup context
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, session)

			if tt.isExternalOrg {
				// Mock the third party integration for syncOrgs call
				thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
				shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

				// Mock the refresh method call
				domainRBAC := mocks.NewAccessControl(t)
				rbacProvider.On("GetDomainRBAC", org.GetID().String()).Return(domainRBAC)
				domainRBAC.On("GetAllProjectsForUser", "user123").Return([]string{}, tt.refreshError)

				if tt.refreshError == nil {
					// RefreshExternalEntityProviderProjects also calls GetAllAssetsForUser
					domainRBAC.On("GetAllAssetsForUser", "user123").Return([]string{}, nil)
					thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return([]models.Project{}, []shared.Role{}, nil)
					projectRepo.On("UpsertSplit", mock.Anything, "gitlab", mock.Anything).Return([]*models.Project{}, []*models.Project{}, nil)
				}
			}

			// Execute
			err := service.TriggerSync(ctx)

			// Assert
			if tt.expectedError {
				assert.Error(t, err)
				if httpErr, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tt.expectedStatus, httpErr.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestFetchExternalProjects(t *testing.T) {
	service := createTestService(t)

	t.Run("successful fetch", func(t *testing.T) {
		ctx := createTestContext()
		projects := []models.Project{{Slug: "project1"}, {Slug: "project2"}}
		roles := []shared.Role{shared.RoleAdmin, shared.RoleMember}

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return(projects, roles, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		resultProjects, resultRoles, err := service.fetchExternalProjects(ctx, "user123", "gitlab")

		assert.NoError(t, err)
		assert.Equal(t, projects, resultProjects)
		assert.Equal(t, roles, resultRoles)
	})

	t.Run("error from third party", func(t *testing.T) {
		ctx := createTestContext()
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return(nil, nil, errors.New("api error"))
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		resultProjects, resultRoles, err := service.fetchExternalProjects(ctx, "user123", "gitlab")

		assert.Error(t, err)
		assert.Nil(t, resultProjects)
		assert.Nil(t, resultRoles)
		assert.Contains(t, err.Error(), "could not list projects for user user123")
	})
}

func TestUpsertProjects(t *testing.T) {
	t.Run("successful upsert", func(t *testing.T) {
		projectRepo := mocks.NewProjectRepository(t)
		service := createTestServiceWithRepo(t, projectRepo)

		org := models.Org{Model: models.Model{ID: uuid.New()}}
		projects := []models.Project{{Slug: "project1"}, {Slug: "project2"}}

		createdPtr := &models.Project{Model: models.Model{ID: uuid.New()}, Slug: "project1"}
		updatedPtr := &models.Project{Model: models.Model{ID: uuid.New()}, Slug: "project2"}

		projectRepo.On("UpsertSplit", mock.Anything, "gitlab", mock.Anything).Return([]*models.Project{createdPtr}, []*models.Project{updatedPtr}, nil)

		created, updated, err := service.upsertProjects(org, projects, "gitlab")

		assert.NoError(t, err)
		assert.Len(t, created, 1)
		assert.Len(t, updated, 1)
		assert.Equal(t, createdPtr.Slug, created[0].Slug)
		assert.Equal(t, updatedPtr.Slug, updated[0].Slug)
	})

	t.Run("repository error", func(t *testing.T) {
		projectRepo := mocks.NewProjectRepository(t)
		service := createTestServiceWithRepo(t, projectRepo)

		org := models.Org{Model: models.Model{ID: uuid.New()}}
		projects := []models.Project{{Slug: "project1"}}

		projectRepo.On("UpsertSplit", mock.Anything, "gitlab", mock.Anything).Return(nil, nil, errors.New("db error"))

		created, updated, err := service.upsertProjects(org, projects, "gitlab")

		assert.Error(t, err)
		assert.Nil(t, created)
		assert.Nil(t, updated)
		assert.Contains(t, err.Error(), "could not upsert projects")
	})
}

func TestEnableCommunityPoliciesForNewProjects(t *testing.T) {
	t.Run("successful enable", func(t *testing.T) {
		projectRepo := mocks.NewProjectRepository(t)
		service := createTestServiceWithRepo(t, projectRepo)

		projects := []models.Project{
			{Model: models.Model{ID: uuid.New()}, Slug: "project1"},
			{Model: models.Model{ID: uuid.New()}, Slug: "project2"},
		}

		for _, project := range projects {
			projectRepo.On("EnableCommunityManagedPolicies", mock.Anything, project.ID).Return(nil)
		}

		err := service.enableCommunityPoliciesForNewProjects(projects)

		assert.NoError(t, err)
		projectRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		projectRepo := mocks.NewProjectRepository(t)
		service := createTestServiceWithRepo(t, projectRepo)

		projects := []models.Project{{Model: models.Model{ID: uuid.New()}, Slug: "project1"}}

		projectRepo.On("EnableCommunityManagedPolicies", mock.Anything, projects[0].ID).Return(errors.New("policy error"))

		err := service.enableCommunityPoliciesForNewProjects(projects)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not enable community managed policies for project project1")
	})
}

func TestSyncOrgs(t *testing.T) {
	t.Run("successful sync with new organizations", func(t *testing.T) {
		ctx := createTestContext()

		// Mock session with user
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user123")
		shared.SetSession(ctx, session)

		// Mock third party integration
		orgs := []models.Org{
			{
				Model:                    models.Model{ID: uuid.New()},
				Slug:                     "org1",
				Name:                     "Organization 1",
				ExternalEntityProviderID: utils.Ptr("github"),
			},
			{
				Model:                    models.Model{ID: uuid.New()},
				Slug:                     "org2",
				Name:                     "Organization 2",
				ExternalEntityProviderID: utils.Ptr("github"),
			},
		}

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return(orgs, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Mock RBAC provider - should call GetDomainRBAC for each org
		rbacProvider := mocks.NewRBACProvider(t)
		domainRBAC1 := mocks.NewAccessControl(t)
		domainRBAC2 := mocks.NewAccessControl(t)

		rbacProvider.On("GetDomainRBAC", orgs[0].GetID().String()).Return(domainRBAC1)
		rbacProvider.On("GetDomainRBAC", orgs[1].GetID().String()).Return(domainRBAC2)

		domainRBAC1.On("GrantRole", "user123", shared.RoleMember).Return(nil)
		domainRBAC2.On("GrantRole", "user123", shared.RoleMember).Return(nil)

		// those orgs have to get bootstrapped - thus mock those function
		domainRBAC1.On("InheritRole", shared.RoleOwner, shared.RoleAdmin).Return(nil)
		domainRBAC2.On("InheritRole", shared.RoleOwner, shared.RoleAdmin).Return(nil)
		domainRBAC1.On("InheritRole", shared.RoleAdmin, shared.RoleMember).Return(nil)
		domainRBAC2.On("InheritRole", shared.RoleAdmin, shared.RoleMember).Return(nil)

		domainRBAC1.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, []shared.Action{shared.ActionDelete}).Return(nil)
		domainRBAC2.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, []shared.Action{shared.ActionDelete}).Return(nil)

		domainRBAC1.On("AllowRole", shared.RoleAdmin, shared.ObjectOrganization, []shared.Action{shared.ActionUpdate}).Return(nil)
		domainRBAC2.On("AllowRole", shared.RoleAdmin, shared.ObjectOrganization, []shared.Action{shared.ActionUpdate}).Return(nil)

		domainRBAC1.On("AllowRole", shared.RoleAdmin, shared.ObjectProject, []shared.Action{shared.ActionCreate, shared.ActionRead, shared.ActionUpdate, shared.ActionDelete}).Return(nil)
		domainRBAC2.On("AllowRole", shared.RoleAdmin, shared.ObjectProject, []shared.Action{shared.ActionCreate, shared.ActionRead, shared.ActionUpdate, shared.ActionDelete}).Return(nil)

		domainRBAC1.On("AllowRole", shared.RoleMember, shared.ObjectOrganization, []shared.Action{shared.ActionRead}).Return(nil)
		domainRBAC2.On("AllowRole", shared.RoleMember, shared.ObjectOrganization, []shared.Action{shared.ActionRead}).Return(nil)

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
			mocks.NewAssetService(t),
			mocks.NewAssetRepository(t),
			mocks.NewProjectRepository(t),
			rbacProvider,
			orgRepo,
		)

		err := serviceWithOrgRepo.TriggerOrgSync(ctx)

		assert.NoError(t, err)
		thirdPartyIntegration.AssertExpectations(t)
		orgRepo.AssertExpectations(t)
		rbacProvider.AssertExpectations(t)
		domainRBAC1.AssertExpectations(t)
		domainRBAC2.AssertExpectations(t)
	})

	t.Run("handles third party integration error", func(t *testing.T) {
		service := createTestService(t)
		ctx := createTestContext()

		// Mock session with user
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user123")
		shared.SetSession(ctx, session)

		// Mock third party integration with error
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return(nil, errors.New("api error"))
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		err := service.TriggerOrgSync(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not list organizations")
		assert.Contains(t, err.Error(), "api error")
		thirdPartyIntegration.AssertExpectations(t)
	})

	t.Run("handles upsert error", func(t *testing.T) {
		ctx := createTestContext()

		// Mock session with user
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user123")
		shared.SetSession(ctx, session)

		// Mock third party integration
		orgs := []models.Org{
			{
				Model:                    models.Model{ID: uuid.New()},
				Slug:                     "org1",
				Name:                     "Organization 1",
				ExternalEntityProviderID: utils.Ptr("github"),
			},
		}
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return(orgs, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository with error
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("database error"))

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
			mocks.NewAssetService(t),
			mocks.NewAssetRepository(t),
			mocks.NewProjectRepository(t),
			mocks.NewRBACProvider(t),
			orgRepo,
		)

		err := serviceWithOrgRepo.TriggerOrgSync(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not upsert organizations")
		assert.Contains(t, err.Error(), "database error")
		thirdPartyIntegration.AssertExpectations(t)
		orgRepo.AssertExpectations(t)
	})

	t.Run("handles rbac grant error but continues", func(t *testing.T) {
		ctx := createTestContext()

		// Mock session with user
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user123")
		shared.SetSession(ctx, session)

		// Mock third party integration
		orgs := []models.Org{
			{
				Model:                    models.Model{ID: uuid.New()},
				Slug:                     "org1",
				Name:                     "Organization 1",
				ExternalEntityProviderID: utils.Ptr("github"),
			},
		}
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return(orgs, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Mock RBAC provider with error
		rbacProvider := mocks.NewRBACProvider(t)
		domainRBAC := mocks.NewAccessControl(t)
		rbacProvider.On("GetDomainRBAC", mock.AnythingOfType("string")).Return(domainRBAC)
		domainRBAC.On("GrantRole", "user123", shared.RoleMember).Return(errors.New("rbac error"))

		// Create service with mocked dependencies
		serviceWithMocks := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
			mocks.NewAssetService(t),
			mocks.NewAssetRepository(t),
			mocks.NewProjectRepository(t),
			rbacProvider,
			orgRepo,
		)

		// Should not return error even if RBAC fails (it just logs a warning)
		err := serviceWithMocks.TriggerOrgSync(ctx)

		assert.NoError(t, err)
		thirdPartyIntegration.AssertExpectations(t)
		orgRepo.AssertExpectations(t)
		rbacProvider.AssertExpectations(t)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("handles empty organization list", func(t *testing.T) {
		ctx := createTestContext()

		// Mock session with user
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("user123")
		shared.SetSession(ctx, session)

		// Mock third party integration with empty list
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return([]models.Org{}, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository - even with empty list, Upsert is still called
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
			mocks.NewAssetService(t),
			mocks.NewAssetRepository(t),
			mocks.NewProjectRepository(t),
			mocks.NewRBACProvider(t),
			orgRepo,
		)

		err := serviceWithOrgRepo.TriggerOrgSync(ctx)

		assert.NoError(t, err)
		thirdPartyIntegration.AssertExpectations(t)
		orgRepo.AssertExpectations(t)
	})
}

func TestCreateProjectsMap(t *testing.T) {
	service := createTestService(t)

	created := []models.Project{
		{Model: models.Model{ID: uuid.New()}, Slug: "created1"},
		{Model: models.Model{ID: uuid.New()}, Slug: "created2"},
	}
	updated := []models.Project{
		{Model: models.Model{ID: uuid.New()}, Slug: "updated1"},
	}

	projectsMap := service.createProjectsMap(created, updated)

	assert.Len(t, projectsMap, 3)
	for _, project := range append(created, updated...) {
		_, exists := projectsMap[project.ID.String()]
		assert.True(t, exists)
	}
}

func TestUpdateUserRole(t *testing.T) {
	service := createTestService(t)

	t.Run("user already has correct role", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(shared.RoleAdmin, nil)

		err := service.updateUserRole(domainRBAC, "user123", shared.RoleAdmin, "project1")

		assert.NoError(t, err)
		// Should not call revoke or grant
		domainRBAC.AssertNotCalled(t, "RevokeRoleInProject")
		domainRBAC.AssertNotCalled(t, "GrantRoleInProject")
	})

	t.Run("role change needed", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(shared.RoleMember, nil)
		domainRBAC.On("RevokeRoleInProject", "user123", shared.RoleMember, "project1").Return(nil)
		domainRBAC.On("GrantRoleInProject", "user123", shared.RoleAdmin, "project1").Return(nil)

		err := service.updateUserRole(domainRBAC, "user123", shared.RoleAdmin, "project1")

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("revoke fails but continues", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(shared.RoleMember, nil)
		domainRBAC.On("RevokeRoleInProject", "user123", shared.RoleMember, "project1").Return(errors.New("revoke failed"))
		domainRBAC.On("GrantRoleInProject", "user123", shared.RoleAdmin, "project1").Return(nil)

		err := service.updateUserRole(domainRBAC, "user123", shared.RoleAdmin, "project1")

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})
}

func TestSyncProjectAssets(t *testing.T) {
	t.Run("successful sync with asset permissions", func(t *testing.T) {
		assetRepo := mocks.NewAssetRepository(t)
		assetService := mocks.NewAssetService(t)
		service := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
			assetService,
			assetRepo,
			mocks.NewProjectRepository(t),
			mocks.NewRBACProvider(t),
			mocks.NewOrganizationRepository(t),
		)

		ctx := createTestContext()
		projectID := uuid.New()
		externalProviderID := "gitlab"
		externalEntityID := "123"

		project := &models.Project{
			Model:                    models.Model{ID: projectID},
			ExternalEntityProviderID: &externalProviderID,
			ExternalEntityID:         &externalEntityID,
		}

		asset1ID := uuid.New()
		asset2ID := uuid.New()
		assets := []models.Asset{
			{Model: models.Model{ID: asset1ID}, Slug: "asset1"},
			{Model: models.Model{ID: asset2ID}, Slug: "asset2"},
		}

		roles := []shared.Role{shared.RoleMember, shared.RoleAdmin}

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListProjects", mock.Anything, "user123", "gitlab", "123").Return(assets, roles, nil)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		assetRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Mock asset bootstrap and permission management
		domainRBAC := mocks.NewAccessControl(t)
		shared.SetRBAC(ctx, domainRBAC)

		assetService.On("BootstrapAsset", domainRBAC, mock.Anything).Return(nil)

		// Mock asset role updates for each asset
		domainRBAC.On("GetAssetRole", "user123", asset1ID.String()).Return(shared.RoleUnknown, errors.New("not found"))
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleUnknown, asset1ID.String()).Return(nil)
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleMember, asset1ID.String()).Return(nil)

		domainRBAC.On("GetAssetRole", "user123", asset2ID.String()).Return(shared.RoleUnknown, errors.New("not found"))
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleUnknown, asset2ID.String()).Return(nil)
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleAdmin, asset2ID.String()).Return(nil)

		result, err := service.syncProjectAssets(ctx, "user123", project)

		assert.NoError(t, err)
		assert.Len(t, result, 2)
		assetRepo.AssertExpectations(t)
		assetService.AssertExpectations(t)
		domainRBAC.AssertExpectations(t)
		thirdPartyIntegration.AssertExpectations(t)
	})

	t.Run("third party error", func(t *testing.T) {
		service := createTestService(t)
		ctx := createTestContext()
		project := &models.Project{
			Model:                    models.Model{ID: uuid.New()},
			ExternalEntityProviderID: utils.Ptr("gitlab"),
			ExternalEntityID:         utils.Ptr("123"),
		}

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListProjects", mock.Anything, "user123", "gitlab", "123").Return(nil, nil, errors.New("api error"))
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		domainRBAC := mocks.NewAccessControl(t)
		shared.SetRBAC(ctx, domainRBAC)

		result, err := service.syncProjectAssets(ctx, "user123", project)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "could not list assets")
	})
}

func TestRevokeAccessForRemovedProjects(t *testing.T) {
	service := createTestService(t)

	t.Run("revoke access for removed projects", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedProjects := []string{"project1", "project2", "project3"}
		projectsMap := map[string]struct{}{
			"project1": {},
			// project2 is missing - should be revoked
			"project3": {},
		}

		domainRBAC.On("RevokeAllRolesInProjectForUser", "user123", "project2").Return(nil)

		service.revokeAccessForRemovedProjects(domainRBAC, "user123", allowedProjects, projectsMap)

		domainRBAC.AssertExpectations(t)
		// Should not call revoke for project1 and project3 as they still exist
		domainRBAC.AssertNotCalled(t, "RevokeAllRolesInProjectForUser", "user123", "project1")
		domainRBAC.AssertNotCalled(t, "RevokeAllRolesInProjectForUser", "user123", "project3")
	})

	t.Run("revoke fails but continues", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedProjects := []string{"project1"}
		projectsMap := map[string]struct{}{}

		domainRBAC.On("RevokeAllRolesInProjectForUser", "user123", "project1").Return(errors.New("revoke failed"))

		// Should not panic
		service.revokeAccessForRemovedProjects(domainRBAC, "user123", allowedProjects, projectsMap)

		domainRBAC.AssertExpectations(t)
	})
}

// Helper functions
func createTestService(t *testing.T) externalEntityProviderService {
	projectService := mocks.NewProjectService(t)
	assetService := mocks.NewAssetService(t)
	assetRepo := mocks.NewAssetRepository(t)
	projectRepo := mocks.NewProjectRepository(t)
	rbacProvider := mocks.NewRBACProvider(t)
	orgRepo := mocks.NewOrganizationRepository(t)

	return NewExternalEntityProviderService(projectService, assetService, assetRepo, projectRepo, rbacProvider, orgRepo)
}

func createTestServiceWithRepo(t *testing.T, projectRepo shared.ProjectRepository) externalEntityProviderService {
	projectService := mocks.NewProjectService(t)
	assetService := mocks.NewAssetService(t)
	assetRepo := mocks.NewAssetRepository(t)
	rbacProvider := mocks.NewRBACProvider(t)
	orgRepo := mocks.NewOrganizationRepository(t)

	return NewExternalEntityProviderService(projectService, assetService, assetRepo, projectRepo, rbacProvider, orgRepo)
}

func createTestContext() shared.Context {
	e := echo.New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

// Asset-level permission tests
func TestUpdateUserRoleInAsset(t *testing.T) {
	service := createTestService(t)

	t.Run("grants new role when user has no current role", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		// User has no current role (returns RoleUnknown with error)
		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleUnknown, errors.New("not found"))
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleUnknown, assetID).Return(nil)
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleMember, assetID).Return(nil)

		err := service.updateUserRoleInAsset(domainRBAC, "user123", shared.RoleMember, assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("updates role when user has different role", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		// User currently has RoleMember, should be upgraded to RoleAdmin
		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleMember, nil)
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleMember, assetID).Return(nil)
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleAdmin, assetID).Return(nil)

		err := service.updateUserRoleInAsset(domainRBAC, "user123", shared.RoleAdmin, assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("does nothing when user already has the role", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		// User already has RoleMember
		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleMember, nil)

		err := service.updateUserRoleInAsset(domainRBAC, "user123", shared.RoleMember, assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
		// Should not call Grant or Revoke
		domainRBAC.AssertNotCalled(t, "GrantRoleInAsset")
		domainRBAC.AssertNotCalled(t, "RevokeRoleInAsset")
	})

	t.Run("does nothing when new role is empty", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		// User has some role but we're not changing it
		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleMember, nil)

		err := service.updateUserRoleInAsset(domainRBAC, "user123", "", assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
		// Should not call Grant or Revoke
		domainRBAC.AssertNotCalled(t, "GrantRoleInAsset")
		domainRBAC.AssertNotCalled(t, "RevokeRoleInAsset")
	})

	t.Run("continues on revoke error", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleMember, nil)
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleMember, assetID).Return(errors.New("revoke failed"))
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleAdmin, assetID).Return(nil)

		err := service.updateUserRoleInAsset(domainRBAC, "user123", shared.RoleAdmin, assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("continues on grant error", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		assetID := uuid.New().String()

		domainRBAC.On("GetAssetRole", "user123", assetID).Return(shared.RoleMember, nil)
		domainRBAC.On("RevokeRoleInAsset", "user123", shared.RoleMember, assetID).Return(nil)
		domainRBAC.On("GrantRoleInAsset", "user123", shared.RoleAdmin, assetID).Return(errors.New("grant failed"))

		err := service.updateUserRoleInAsset(domainRBAC, "user123", shared.RoleAdmin, assetID)

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})
}

func TestRevokeAccessForRemovedAssets(t *testing.T) {
	service := createTestService(t)

	t.Run("revokes access for removed assets", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedAssets := []string{"asset1", "asset2", "asset3"}
		assetsMap := map[string]struct{}{
			"asset1": {},
			"asset3": {},
		}

		// asset2 no longer exists, should revoke
		domainRBAC.On("RevokeAllRolesInAssetForUser", "user123", "asset2").Return(nil)

		service.revokeAccessForRemovedAssets(domainRBAC, "user123", allowedAssets, assetsMap)

		domainRBAC.AssertExpectations(t)
		// Should not call revoke for asset1 and asset3 as they still exist
		domainRBAC.AssertNotCalled(t, "RevokeAllRolesInAssetForUser", "user123", "asset1")
		domainRBAC.AssertNotCalled(t, "RevokeAllRolesInAssetForUser", "user123", "asset3")
	})

	t.Run("revoke fails but continues", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedAssets := []string{"asset1"}
		assetsMap := map[string]struct{}{}

		domainRBAC.On("RevokeAllRolesInAssetForUser", "user123", "asset1").Return(errors.New("revoke failed"))

		// Should not panic
		service.revokeAccessForRemovedAssets(domainRBAC, "user123", allowedAssets, assetsMap)

		domainRBAC.AssertExpectations(t)
	})

	t.Run("handles empty allowed assets list", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedAssets := []string{}
		assetsMap := map[string]struct{}{
			"asset1": {},
		}

		// Should not panic and not call anything
		service.revokeAccessForRemovedAssets(domainRBAC, "user123", allowedAssets, assetsMap)

		domainRBAC.AssertExpectations(t)
		domainRBAC.AssertNotCalled(t, "RevokeAllRolesInAssetForUser")
	})

	t.Run("handles empty assets map", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)

		allowedAssets := []string{"asset1", "asset2"}
		assetsMap := map[string]struct{}{}

		// All assets removed, should revoke all
		domainRBAC.On("RevokeAllRolesInAssetForUser", "user123", "asset1").Return(nil)
		domainRBAC.On("RevokeAllRolesInAssetForUser", "user123", "asset2").Return(nil)

		service.revokeAccessForRemovedAssets(domainRBAC, "user123", allowedAssets, assetsMap)

		domainRBAC.AssertExpectations(t)
	})
}
