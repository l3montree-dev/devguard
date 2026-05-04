package accesscontrol

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3"
	casbinModel "github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/l3montree-dev/devguard/shared"
)

// noopAdapter is a minimal adapter for tests. Policy rules are kept
// in-memory by casbin's model layer; this adapter only satisfies the interface.
type noopAdapter struct{}

func (noopAdapter) LoadPolicy(_ casbinModel.Model) error                        { return nil }
func (noopAdapter) SavePolicy(_ casbinModel.Model) error                        { return nil }
func (noopAdapter) AddPolicy(_, _ string, _ []string) error                     { return nil }
func (noopAdapter) RemovePolicy(_, _ string, _ []string) error                  { return nil }
func (noopAdapter) RemoveFilteredPolicy(_, _ string, _ int, _ ...string) error  { return nil }
func (noopAdapter) LoadPolicyCtx(_ context.Context, _ casbinModel.Model) error  { return nil }
func (noopAdapter) SavePolicyCtx(_ context.Context, _ casbinModel.Model) error  { return nil }
func (noopAdapter) AddPolicyCtx(_ context.Context, _, _ string, _ []string) error { return nil }
func (noopAdapter) RemovePolicyCtx(_ context.Context, _, _ string, _ []string) error { return nil }
func (noopAdapter) RemoveFilteredPolicyCtx(_ context.Context, _, _ string, _ int, _ ...string) error {
	return nil
}

var _ persist.ContextAdapter = noopAdapter{}

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

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i)
			project := fmt.Sprintf("project-%d", i%5)
			_ = rbac.GrantRoleInProject(context.Background(), user, shared.RoleMember, project)
			_ = rbac.RevokeRoleInProject(context.Background(), user, shared.RoleMember, project)
		}()
	}
	wg.Wait()
}

func TestCasbinRBAC_ConcurrentReads(t *testing.T) {
	rbac := newTestCasbinRBAC(t, "org-1")

	// Seed some data first.
	for i := 0; i < 5; i++ {
		_ = rbac.GrantRoleInProject(context.Background(), fmt.Sprintf("user-%d", i), shared.RoleMember, "project-0")
	}

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i%5)
			_ = rbac.GetAllRoles(user)
			_, _ = rbac.GetAllProjectsForUser(user)
		}()
	}
	wg.Wait()
}

func TestCasbinRBAC_ConcurrentReadsAndWrites(t *testing.T) {
	rbac := newTestCasbinRBAC(t, "org-1")

	const goroutines = 40
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", i%10)
			project := fmt.Sprintf("project-%d", i%3)
			if i%2 == 0 {
				_ = rbac.GrantRoleInProject(context.Background(), user, shared.RoleMember, project)
			} else {
				_ = rbac.GetAllRoles(user)
				_, _ = rbac.GetAllProjectsForUser(user)
			}
		}()
	}
	wg.Wait()
}

// TestCasbinRBAC_TwoUsersConcurrentOrgSync mirrors the exact scenario from the panic:
// two users trigger RefreshExternalEntityProviderProjects for the same org simultaneously.
// singleflight deduplicates per org+user, so both goroutines run concurrently and both
// call casbin write operations on the shared enforcer.
func TestCasbinRBAC_TwoUsersConcurrentOrgSync(t *testing.T) {
	// Both users share the same enforcer (same org, different singleflight keys).
	sharedEnforcer := newTestEnforcer(t)

	user1rbac := &casbinRBAC{domain: "org-1", enforcer: sharedEnforcer}
	user2rbac := &casbinRBAC{domain: "org-1", enforcer: sharedEnforcer}

	projects := []string{"proj-a", "proj-b", "proj-c", "proj-d", "proj-e"}

	var wg sync.WaitGroup
	for _, rbac := range []*casbinRBAC{user1rbac, user2rbac} {
		rbac := rbac
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Simulate what syncProjectsAndAssets does: grant + read roles per project.
			for _, project := range projects {
				_ = rbac.GrantRoleInProject(context.Background(), "user", shared.RoleMember, project)
				_ = rbac.GetAllRoles("user")
				_ = rbac.RevokeAllRolesInProjectForUser(context.Background(), "user", project)
			}
		}()
	}
	wg.Wait()
}
