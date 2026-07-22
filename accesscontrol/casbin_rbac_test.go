package accesscontrol

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3"
	casbinModel "github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

// noopAdapter is a minimal adapter for tests. Policy rules are kept
// in-memory by casbin's model layer; this adapter only satisfies the interface.
type noopAdapter struct{}

func (noopAdapter) LoadPolicy(_ casbinModel.Model) error                             { return nil }
func (noopAdapter) SavePolicy(_ casbinModel.Model) error                             { return nil }
func (noopAdapter) AddPolicy(_, _ string, _ []string) error                          { return nil }
func (noopAdapter) RemovePolicy(_, _ string, _ []string) error                       { return nil }
func (noopAdapter) RemoveFilteredPolicy(_, _ string, _ int, _ ...string) error       { return nil }
func (noopAdapter) LoadPolicyCtx(_ context.Context, _ casbinModel.Model) error       { return nil }
func (noopAdapter) SavePolicyCtx(_ context.Context, _ casbinModel.Model) error       { return nil }
func (noopAdapter) AddPolicyCtx(_ context.Context, _, _ string, _ []string) error    { return nil }
func (noopAdapter) RemovePolicyCtx(_ context.Context, _, _ string, _ []string) error { return nil }
func (noopAdapter) RemoveFilteredPolicyCtx(_ context.Context, _, _ string, _ int, _ ...string) error {
	return nil
}
func (noopAdapter) AddPoliciesCtx(_ context.Context, _, _ string, _ [][]string) error    { return nil }
func (noopAdapter) RemovePoliciesCtx(_ context.Context, _, _ string, _ [][]string) error { return nil }

var _ persist.ContextBatchAdapter = noopAdapter{}

// testModelText mirrors config/rbac_model.conf so tests are self-contained.
const testModelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

func newTestEnforcer(t *testing.T) *casbin.ContextEnforcer {
	t.Helper()
	m, err := casbinModel.NewModelFromString(testModelText)
	if err != nil {
		t.Fatalf("create casbin model: %v", err)
	}
	iface, err := casbin.NewContextEnforcer(m, noopAdapter{})
	if err != nil {
		t.Fatalf("create casbin enforcer: %v", err)
	}
	return iface.(*casbin.ContextEnforcer)
}

func newTestCasbinRBAC(t *testing.T, domain string) *casbinRBAC {
	t.Helper()
	return &casbinRBAC{domain: domain, enforcer: newTestEnforcer(t)}
}

// TestCasbinRBAC_ConcurrentWrites is a regression test for the panic:
// "fatal error: concurrent map read and map write" inside casbin's Model.RemovePolicy.
// Before the casbinMu fix, concurrent goroutines (e.g. different users triggering sync
// via ErrGroup) wrote to casbin's internal policy maps without any synchronisation.
func TestCasbinRBAC_ConcurrentWrites(t *testing.T) {
	rbac := newTestCasbinRBAC(t, "org-1")

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i)
			project := fmt.Sprintf("project-%d", i%5)
			_ = rbac.GrantRoleInProject(context.Background(), shared.NewSession(user, shared.SessionActorUser, nil, false), shared.RoleMember, project)
			_ = rbac.RevokeRoleInProject(context.Background(), shared.NewSession(user, shared.SessionActorUser, nil, false), shared.RoleMember, project)
		}()
	}
	wg.Wait()
}

func TestCasbinRBAC_ConcurrentReads(t *testing.T) {
	rbac := newTestCasbinRBAC(t, "org-1")

	// Seed some data first.
	for i := range 5 {
		_ = rbac.GrantRoleInProject(context.Background(), shared.NewSession(fmt.Sprintf("user-%d", i), shared.SessionActorUser, nil, false), shared.RoleMember, "project-0")
	}

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i%5)
			_ = rbac.GetAllRoles(user)
			_, _ = rbac.GetAllProjectsForSession(context.Background(), shared.NewSession(user, shared.SessionActorUser, nil, false))
		}()
	}
	wg.Wait()
}

func TestCasbinRBAC_ConcurrentReadsAndWrites(t *testing.T) {
	rbac := newTestCasbinRBAC(t, "org-1")

	const goroutines = 40
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i%10)
			project := fmt.Sprintf("project-%d", i%3)
			if i%2 == 0 {
				_ = rbac.GrantRoleInProject(context.Background(), shared.NewSession(user, shared.SessionActorUser, nil, false), shared.RoleMember, project)
			} else {
				_ = rbac.GetAllRoles(user)
				_, _ = rbac.GetAllProjectsForSession(context.Background(), shared.NewSession(user, shared.SessionActorUser, nil, false))
			}
		}()
	}
	wg.Wait()
}

// TestRevokeAllRolesInProject_RemovesRolesButKeepsSiblings is the core test for
// revokeAllRolesForPrefix: every role inside the project is removed while a sibling
// project whose id shares the same string prefix must stay untouched. This guards the
// trailing "|" in the revoke prefix (without it, "proj" would also match "proj-2").
func TestRevokeAllRolesInProjectRemovesRolesButKeepsSiblings(t *testing.T) {
	ctx := context.Background()
	rbac := newTestCasbinRBAC(t, "org-1")

	if err := rbac.GrantRoleInProject(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false), shared.RoleAdmin, "proj"); err != nil {
		t.Fatal(err)
	}
	if err := rbac.GrantRoleInProject(ctx, shared.NewSession("bob", shared.SessionActorUser, nil, false), shared.RoleMember, "proj"); err != nil {
		t.Fatal(err)
	}
	// carol lives in a sibling project that shares the "proj" prefix
	if err := rbac.GrantRoleInProject(ctx, shared.NewSession("carol", shared.SessionActorUser, nil, false), shared.RoleAdmin, "proj-2"); err != nil {
		t.Fatal(err)
	}
	// role-to-role grouping inside "proj" (admin inherits member) must be removed too
	if err := rbac.InheritProjectRole(ctx, shared.RoleAdmin, shared.RoleMember, "proj"); err != nil {
		t.Fatal(err)
	}

	if err := rbac.RevokeAllRolesInProject(ctx, "proj"); err != nil {
		t.Fatalf("RevokeAllRolesInProject: %v", err)
	}

	// every role inside "proj" is gone
	if _, err := rbac.GetProjectRole("alice", "proj"); err == nil {
		t.Error("alice still has a role in proj")
	}
	if _, err := rbac.GetProjectRole("bob", "proj"); err == nil {
		t.Error("bob still has a role in proj")
	}
	if projects, _ := rbac.GetAllProjectsForSession(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false)); len(projects) != 0 {
		t.Errorf("alice still mapped to projects: %v", projects)
	}

	// the sibling project sharing the "proj" prefix is untouched
	role, err := rbac.GetProjectRole("carol", "proj-2")
	if err != nil {
		t.Fatalf("carol lost her role in proj-2: %v", err)
	}
	if role != shared.RoleAdmin {
		t.Errorf("expected carol to keep admin in proj-2, got %q", role)
	}
}

// TestRevokeAllRolesInProject_RemovesPolicies verifies the second branch of
// revokeAllRolesForPrefix: permission policies (p rules) scoped to the project are deleted.
func TestRevokeAllRolesInProjectRemovesPolicies(t *testing.T) {
	ctx := context.Background()
	rbac := newTestCasbinRBAC(t, "org-1")

	project := &models.Project{Model: models.Model{ID: uuid.New()}}
	projectID := project.ID.String()

	if err := rbac.GrantRoleInProject(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false), shared.RoleAdmin, projectID); err != nil {
		t.Fatal(err)
	}
	if err := rbac.AllowRoleInProject(ctx, projectID, shared.RoleAdmin, shared.ObjectProject, []shared.Action{shared.ActionRead}); err != nil {
		t.Fatal(err)
	}

	alice := shared.NewSession("alice", shared.SessionActorUser, nil, false)
	allowed, err := rbac.IsAllowedInProject(ctx, project, alice, shared.ObjectProject, shared.ActionRead)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("alice should be allowed before revoking")
	}

	if err := rbac.RevokeAllRolesInProject(ctx, projectID); err != nil {
		t.Fatalf("RevokeAllRolesInProject: %v", err)
	}

	allowed, err = rbac.IsAllowedInProject(ctx, project, alice, shared.ObjectProject, shared.ActionRead)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("alice should no longer be allowed after revoking the project roles and policies")
	}
}

// TestRevokeAllRolesInAsset_RemovesRolesButKeepsSiblings mirrors the project test for assets.
func TestRevokeAllRolesInAssetRemovesRolesButKeepsSiblings(t *testing.T) {
	ctx := context.Background()
	rbac := newTestCasbinRBAC(t, "org-1")

	if err := rbac.GrantRoleInAsset(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false), shared.RoleAdmin, "asset"); err != nil {
		t.Fatal(err)
	}
	if err := rbac.GrantRoleInAsset(ctx, shared.NewSession("carol", shared.SessionActorUser, nil, false), shared.RoleAdmin, "asset-2"); err != nil {
		t.Fatal(err)
	}

	if err := rbac.RevokeAllRolesInAsset(ctx, "asset"); err != nil {
		t.Fatalf("RevokeAllRolesInAsset: %v", err)
	}

	if _, err := rbac.GetAssetRole("alice", "asset"); err == nil {
		t.Error("alice still has a role in asset")
	}
	role, err := rbac.GetAssetRole("carol", "asset-2")
	if err != nil {
		t.Fatalf("carol lost her role in asset-2: %v", err)
	}
	if role != shared.RoleAdmin {
		t.Errorf("expected carol to keep admin in asset-2, got %q", role)
	}
}

// TestGetAllProjectsForSession_OwnerTypes covers the access-token-type dispatch
// in GetAllProjectsForSession: a user session resolves projects via casbin roles,
// an org session lists every project of the org (repository lookup), a project
// session is scoped to itself, and an asset session has no projects.
func TestGetAllProjectsForSessionOwnerTypes(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	projectID := uuid.New()

	t.Run("user owner resolves projects from granted roles", func(t *testing.T) {
		rbac := newTestCasbinRBAC(t, "org-1")
		if err := rbac.GrantRoleInProject(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false), shared.RoleMember, projectID.String()); err != nil {
			t.Fatal(err)
		}

		projects, err := rbac.GetAllProjectsForSession(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(projects) != 1 || projects[0] != projectID.String() {
			t.Errorf("expected [%s], got %v", projectID, projects)
		}
	})

	t.Run("org owner lists all projects of the organization", func(t *testing.T) {
		projectRepo := mocks.NewProjectRepository(t)
		projectRepo.EXPECT().GetByOrgID(ctx, (*gorm.DB)(nil), orgID).Return([]models.Project{{Model: models.Model{ID: projectID}}}, nil)
		rbac := &casbinRBAC{domain: "org-1", enforcer: newTestEnforcer(t), projectRepository: projectRepo}

		projects, err := rbac.GetAllProjectsForSession(ctx, shared.NewSession(orgID.String(), shared.SessionActorOrg, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(projects) != 1 || projects[0] != projectID.String() {
			t.Errorf("expected [%s], got %v", projectID, projects)
		}
	})

	t.Run("project owner is scoped to itself", func(t *testing.T) {
		rbac := newTestCasbinRBAC(t, "org-1")

		projects, err := rbac.GetAllProjectsForSession(ctx, shared.NewSession(projectID.String(), shared.SessionActorProject, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(projects) != 1 || projects[0] != projectID.String() {
			t.Errorf("expected [%s], got %v", projectID, projects)
		}
	})

	t.Run("asset owner has no projects", func(t *testing.T) {
		rbac := newTestCasbinRBAC(t, "org-1")

		projects, err := rbac.GetAllProjectsForSession(ctx, shared.NewSession(uuid.New().String(), shared.SessionActorAsset, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(projects) != 0 {
			t.Errorf("expected no projects, got %v", projects)
		}
	})
}

// TestGetAllAssetsForSession_OwnerTypes mirrors TestGetAllProjectsForSession_OwnerTypes
// for GetAllAssetsForSession: user->roles, org->all assets of org, project->all assets
// of the project, asset->itself.
func TestGetAllAssetsForSessionOwnerTypes(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	projectID := uuid.New()
	assetID := uuid.New()

	t.Run("user owner resolves assets from granted roles", func(t *testing.T) {
		rbac := newTestCasbinRBAC(t, "org-1")
		if err := rbac.GrantRoleInAsset(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false), shared.RoleMember, assetID.String()); err != nil {
			t.Fatal(err)
		}

		assets, err := rbac.GetAllAssetsForSession(ctx, shared.NewSession("alice", shared.SessionActorUser, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) != 1 || assets[0] != assetID.String() {
			t.Errorf("expected [%s], got %v", assetID, assets)
		}
	})

	t.Run("org owner lists all assets of the organization", func(t *testing.T) {
		assetRepo := mocks.NewAssetRepository(t)
		assetRepo.EXPECT().GetByOrgID(ctx, (*gorm.DB)(nil), orgID).Return([]models.Asset{{Model: models.Model{ID: assetID}}}, nil)
		rbac := &casbinRBAC{domain: "org-1", enforcer: newTestEnforcer(t), assetRepository: assetRepo}

		assets, err := rbac.GetAllAssetsForSession(ctx, shared.NewSession(orgID.String(), shared.SessionActorOrg, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) != 1 || assets[0] != assetID.String() {
			t.Errorf("expected [%s], got %v", assetID, assets)
		}
	})

	t.Run("project owner lists all assets of the project", func(t *testing.T) {
		assetRepo := mocks.NewAssetRepository(t)
		assetRepo.EXPECT().GetByProjectID(ctx, (*gorm.DB)(nil), projectID).Return([]models.Asset{{Model: models.Model{ID: assetID}}}, nil)
		rbac := &casbinRBAC{domain: "org-1", enforcer: newTestEnforcer(t), assetRepository: assetRepo}

		assets, err := rbac.GetAllAssetsForSession(ctx, shared.NewSession(projectID.String(), shared.SessionActorProject, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) != 1 || assets[0] != assetID.String() {
			t.Errorf("expected [%s], got %v", assetID, assets)
		}
	})

	t.Run("asset owner is scoped to itself", func(t *testing.T) {
		rbac := newTestCasbinRBAC(t, "org-1")

		assets, err := rbac.GetAllAssetsForSession(ctx, shared.NewSession(assetID.String(), shared.SessionActorAsset, nil, false))
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) != 1 || assets[0] != assetID.String() {
			t.Errorf("expected [%s], got %v", assetID, assets)
		}
	})
}

// TestCasbinRBAC_TwoUsersConcurrentOrgSync mirrors the exact scenario from the panic:
// two users trigger RefreshExternalEntityProviderProjects for the same org simultaneously.
// singleflight deduplicates per org+user, so both goroutines run concurrently and both
// call casbin write operations on the shared enforcer.
func TestCasbinRBACTwoUsersConcurrentOrgSync(t *testing.T) {
	// Both users share the same enforcer (same org, different singleflight keys).
	sharedEnforcer := newTestEnforcer(t)

	user1rbac := &casbinRBAC{domain: "org-1", enforcer: sharedEnforcer}
	user2rbac := &casbinRBAC{domain: "org-1", enforcer: sharedEnforcer}

	projects := []string{"proj-a", "proj-b", "proj-c", "proj-d", "proj-e"}

	var wg sync.WaitGroup
	for _, rbac := range []*casbinRBAC{user1rbac, user2rbac} {
		wg.Go(func() {
			// Simulate what syncProjectsAndAssets does: grant + read roles per project.
			for _, project := range projects {
				_ = rbac.GrantRoleInProject(context.Background(), shared.NewSession("user", shared.SessionActorUser, nil, false), shared.RoleMember, project)
				_ = rbac.GetAllRoles("user")
				_ = rbac.RevokeAllRolesInProjectForUser(context.Background(), "user", project)
			}
		})
	}
	wg.Wait()
}
