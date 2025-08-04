package integrations

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
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
			assetRepo := mocks.NewAssetRepository(t)
			projectRepo := mocks.NewProjectRepository(t)
			rbacProvider := mocks.NewRBACProvider(t)
			orgRepo := mocks.NewOrganizationRepository(t)

			service := NewExternalEntityProviderService(projectService, assetRepo, projectRepo, rbacProvider, orgRepo)

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
			core.SetOrg(ctx, org)
			core.SetSession(ctx, session)

			if tt.isExternalOrg {
				// Mock the third party integration for syncOrgs call
				thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
				core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

				// Mock the refresh method call
				domainRBAC := mocks.NewAccessControl(t)
				rbacProvider.On("GetDomainRBAC", org.GetID().String()).Return(domainRBAC)
				domainRBAC.On("GetAllProjectsForUser", "user123").Return([]string{}, tt.refreshError)

				if tt.refreshError == nil {
					thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return([]models.Project{}, []core.Role{}, nil)
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

func TestGetAllowedProjectsForUser(t *testing.T) {
	service := createTestService(t)

	t.Run("successful fetch", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetAllProjectsForUser", "user123").Return([]string{"project1", "project2"}, nil)

		result, err := service.getAllowedProjectsForUser(domainRBAC, "user123")

		assert.NoError(t, err)
		assert.Equal(t, []string{"project1", "project2"}, result)
	})

	t.Run("error from RBAC", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetAllProjectsForUser", "user123").Return(nil, errors.New("rbac error"))

		result, err := service.getAllowedProjectsForUser(domainRBAC, "user123")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "could not get allowed projects for user user123")
	})
}

func TestFetchExternalProjects(t *testing.T) {
	service := createTestService(t)

	t.Run("successful fetch", func(t *testing.T) {
		ctx := createTestContext()
		projects := []models.Project{{Slug: "project1"}, {Slug: "project2"}}
		roles := []core.Role{core.RoleAdmin, core.RoleMember}

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return(projects, roles, nil)
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		resultProjects, resultRoles, err := service.fetchExternalProjects(ctx, "user123", "gitlab")

		assert.NoError(t, err)
		assert.Equal(t, projects, resultProjects)
		assert.Equal(t, roles, resultRoles)
	})

	t.Run("error from third party", func(t *testing.T) {
		ctx := createTestContext()
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListGroups", mock.Anything, "user123", "gitlab").Return(nil, nil, errors.New("api error"))
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

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
		core.SetSession(ctx, session)

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
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Mock RBAC provider - should call GetDomainRBAC for each org
		rbacProvider := mocks.NewRBACProvider(t)
		domainRBAC1 := mocks.NewAccessControl(t)
		domainRBAC2 := mocks.NewAccessControl(t)

		rbacProvider.On("GetDomainRBAC", orgs[0].GetID().String()).Return(domainRBAC1)
		rbacProvider.On("GetDomainRBAC", orgs[1].GetID().String()).Return(domainRBAC2)

		domainRBAC1.On("GrantRole", "user123", core.RoleMember).Return(nil)
		domainRBAC2.On("GrantRole", "user123", core.RoleMember).Return(nil)

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
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
		core.SetSession(ctx, session)

		// Mock third party integration with error
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return(nil, errors.New("api error"))
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

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
		core.SetSession(ctx, session)

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
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository with error
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("database error"))

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
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
		core.SetSession(ctx, session)

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
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Mock RBAC provider with error
		rbacProvider := mocks.NewRBACProvider(t)
		domainRBAC := mocks.NewAccessControl(t)
		rbacProvider.On("GetDomainRBAC", mock.AnythingOfType("string")).Return(domainRBAC)
		domainRBAC.On("GrantRole", "user123", core.RoleMember).Return(errors.New("rbac error"))

		// Create service with mocked dependencies
		serviceWithMocks := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
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
		core.SetSession(ctx, session)

		// Mock third party integration with empty list
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListOrgs", ctx).Return([]models.Org{}, nil)
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		// Mock organization repository - even with empty list, Upsert is still called
		orgRepo := mocks.NewOrganizationRepository(t)
		orgRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		// Create service with mocked org repo
		serviceWithOrgRepo := NewExternalEntityProviderService(
			mocks.NewProjectService(t),
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
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(core.RoleAdmin, nil)

		err := service.updateUserRole(domainRBAC, "user123", core.RoleAdmin, "project1")

		assert.NoError(t, err)
		// Should not call revoke or grant
		domainRBAC.AssertNotCalled(t, "RevokeRoleInProject")
		domainRBAC.AssertNotCalled(t, "GrantRoleInProject")
	})

	t.Run("role change needed", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(core.RoleMember, nil)
		domainRBAC.On("RevokeRoleInProject", "user123", core.RoleMember, "project1").Return(nil)
		domainRBAC.On("GrantRoleInProject", "user123", core.RoleAdmin, "project1").Return(nil)

		err := service.updateUserRole(domainRBAC, "user123", core.RoleAdmin, "project1")

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})

	t.Run("revoke fails but continues", func(t *testing.T) {
		domainRBAC := mocks.NewAccessControl(t)
		domainRBAC.On("GetProjectRole", "user123", "project1").Return(core.RoleMember, nil)
		domainRBAC.On("RevokeRoleInProject", "user123", core.RoleMember, "project1").Return(errors.New("revoke failed"))
		domainRBAC.On("GrantRoleInProject", "user123", core.RoleAdmin, "project1").Return(nil)

		err := service.updateUserRole(domainRBAC, "user123", core.RoleAdmin, "project1")

		assert.NoError(t, err)
		domainRBAC.AssertExpectations(t)
	})
}

func TestSyncProjectAssets(t *testing.T) {
	t.Run("successful sync", func(t *testing.T) {
		assetRepo := mocks.NewAssetRepository(t)
		service := createTestServiceWithAssetRepo(t, assetRepo)

		ctx := createTestContext()
		project := &models.Project{
			Model:                    models.Model{ID: uuid.New()},
			ExternalEntityProviderID: utils.Ptr("gitlab"),
			ExternalEntityID:         utils.Ptr("123"),
		}

		assets := []models.Asset{{Slug: "asset1"}, {Slug: "asset2"}}
		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("ListProjects", mock.Anything, "user123", "gitlab", "123").Return(assets, nil, nil)
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		assetRepo.On("Upsert", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		err := service.syncProjectAssets(ctx, "user123", project)

		assert.NoError(t, err)
		assetRepo.AssertExpectations(t)
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
		core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		err := service.syncProjectAssets(ctx, "user123", project)

		assert.Error(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, 500, httpErr.Code)
		}
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
	assetRepo := mocks.NewAssetRepository(t)
	projectRepo := mocks.NewProjectRepository(t)
	rbacProvider := mocks.NewRBACProvider(t)
	orgRepo := mocks.NewOrganizationRepository(t)

	return NewExternalEntityProviderService(projectService, assetRepo, projectRepo, rbacProvider, orgRepo)
}

func createTestServiceWithRepo(t *testing.T, projectRepo core.ProjectRepository) externalEntityProviderService {
	projectService := mocks.NewProjectService(t)
	assetRepo := mocks.NewAssetRepository(t)
	rbacProvider := mocks.NewRBACProvider(t)
	orgRepo := mocks.NewOrganizationRepository(t)

	return NewExternalEntityProviderService(projectService, assetRepo, projectRepo, rbacProvider, orgRepo)
}

func createTestServiceWithAssetRepo(t *testing.T, assetRepo core.AssetRepository) externalEntityProviderService {
	projectService := mocks.NewProjectService(t)
	projectRepo := mocks.NewProjectRepository(t)
	rbacProvider := mocks.NewRBACProvider(t)
	orgRepo := mocks.NewOrganizationRepository(t)

	return NewExternalEntityProviderService(projectService, assetRepo, projectRepo, rbacProvider, orgRepo)
}

func createTestContext() core.Context {
	e := echo.New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}
