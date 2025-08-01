// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"context"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// NewThirdPartyIntegration creates a new instance of ThirdPartyIntegration. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewThirdPartyIntegration(t interface {
	mock.TestingT
	Cleanup(func())
}) *ThirdPartyIntegration {
	mock := &ThirdPartyIntegration{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// ThirdPartyIntegration is an autogenerated mock type for the ThirdPartyIntegration type
type ThirdPartyIntegration struct {
	mock.Mock
}

type ThirdPartyIntegration_Expecter struct {
	mock *mock.Mock
}

func (_m *ThirdPartyIntegration) EXPECT() *ThirdPartyIntegration_Expecter {
	return &ThirdPartyIntegration_Expecter{mock: &_m.Mock}
}

// CreateIssue provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	ret := _mock.Called(ctx, asset, assetVersionName, vuln, projectSlug, orgSlug, justification, userID)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssue")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, models.Asset, string, models.Vuln, string, string, string, string) error); ok {
		r0 = returnFunc(ctx, asset, assetVersionName, vuln, projectSlug, orgSlug, justification, userID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ThirdPartyIntegration_CreateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssue'
type ThirdPartyIntegration_CreateIssue_Call struct {
	*mock.Call
}

// CreateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - asset models.Asset
//   - assetVersionName string
//   - vuln models.Vuln
//   - projectSlug string
//   - orgSlug string
//   - justification string
//   - userID string
func (_e *ThirdPartyIntegration_Expecter) CreateIssue(ctx interface{}, asset interface{}, assetVersionName interface{}, vuln interface{}, projectSlug interface{}, orgSlug interface{}, justification interface{}, userID interface{}) *ThirdPartyIntegration_CreateIssue_Call {
	return &ThirdPartyIntegration_CreateIssue_Call{Call: _e.mock.On("CreateIssue", ctx, asset, assetVersionName, vuln, projectSlug, orgSlug, justification, userID)}
}

func (_c *ThirdPartyIntegration_CreateIssue_Call) Run(run func(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string)) *ThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 models.Asset
		if args[1] != nil {
			arg1 = args[1].(models.Asset)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		var arg3 models.Vuln
		if args[3] != nil {
			arg3 = args[3].(models.Vuln)
		}
		var arg4 string
		if args[4] != nil {
			arg4 = args[4].(string)
		}
		var arg5 string
		if args[5] != nil {
			arg5 = args[5].(string)
		}
		var arg6 string
		if args[6] != nil {
			arg6 = args[6].(string)
		}
		var arg7 string
		if args[7] != nil {
			arg7 = args[7].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
			arg4,
			arg5,
			arg6,
			arg7,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_CreateIssue_Call) Return(err error) *ThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ThirdPartyIntegration_CreateIssue_Call) RunAndReturn(run func(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error) *ThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// GetID provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) GetID() core.IntegrationID {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetID")
	}

	var r0 core.IntegrationID
	if returnFunc, ok := ret.Get(0).(func() core.IntegrationID); ok {
		r0 = returnFunc()
	} else {
		r0 = ret.Get(0).(core.IntegrationID)
	}
	return r0
}

// ThirdPartyIntegration_GetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetID'
type ThirdPartyIntegration_GetID_Call struct {
	*mock.Call
}

// GetID is a helper method to define mock.On call
func (_e *ThirdPartyIntegration_Expecter) GetID() *ThirdPartyIntegration_GetID_Call {
	return &ThirdPartyIntegration_GetID_Call{Call: _e.mock.On("GetID")}
}

func (_c *ThirdPartyIntegration_GetID_Call) Run(run func()) *ThirdPartyIntegration_GetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ThirdPartyIntegration_GetID_Call) Return(integrationID core.IntegrationID) *ThirdPartyIntegration_GetID_Call {
	_c.Call.Return(integrationID)
	return _c
}

func (_c *ThirdPartyIntegration_GetID_Call) RunAndReturn(run func() core.IntegrationID) *ThirdPartyIntegration_GetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) GetUsers(org models.Org) []core.User {
	ret := _mock.Called(org)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []core.User
	if returnFunc, ok := ret.Get(0).(func(models.Org) []core.User); ok {
		r0 = returnFunc(org)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.User)
		}
	}
	return r0
}

// ThirdPartyIntegration_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type ThirdPartyIntegration_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - org models.Org
func (_e *ThirdPartyIntegration_Expecter) GetUsers(org interface{}) *ThirdPartyIntegration_GetUsers_Call {
	return &ThirdPartyIntegration_GetUsers_Call{Call: _e.mock.On("GetUsers", org)}
}

func (_c *ThirdPartyIntegration_GetUsers_Call) Run(run func(org models.Org)) *ThirdPartyIntegration_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Org
		if args[0] != nil {
			arg0 = args[0].(models.Org)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_GetUsers_Call) Return(users []core.User) *ThirdPartyIntegration_GetUsers_Call {
	_c.Call.Return(users)
	return _c
}

func (_c *ThirdPartyIntegration_GetUsers_Call) RunAndReturn(run func(org models.Org) []core.User) *ThirdPartyIntegration_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

// HandleEvent provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) HandleEvent(event any) error {
	ret := _mock.Called(event)

	if len(ret) == 0 {
		panic("no return value specified for HandleEvent")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(any) error); ok {
		r0 = returnFunc(event)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ThirdPartyIntegration_HandleEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleEvent'
type ThirdPartyIntegration_HandleEvent_Call struct {
	*mock.Call
}

// HandleEvent is a helper method to define mock.On call
//   - event any
func (_e *ThirdPartyIntegration_Expecter) HandleEvent(event interface{}) *ThirdPartyIntegration_HandleEvent_Call {
	return &ThirdPartyIntegration_HandleEvent_Call{Call: _e.mock.On("HandleEvent", event)}
}

func (_c *ThirdPartyIntegration_HandleEvent_Call) Run(run func(event any)) *ThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 any
		if args[0] != nil {
			arg0 = args[0].(any)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_HandleEvent_Call) Return(err error) *ThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ThirdPartyIntegration_HandleEvent_Call) RunAndReturn(run func(event any) error) *ThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Return(run)
	return _c
}

// HandleWebhook provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) HandleWebhook(ctx core.Context) error {
	ret := _mock.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for HandleWebhook")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.Context) error); ok {
		r0 = returnFunc(ctx)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ThirdPartyIntegration_HandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleWebhook'
type ThirdPartyIntegration_HandleWebhook_Call struct {
	*mock.Call
}

// HandleWebhook is a helper method to define mock.On call
//   - ctx core.Context
func (_e *ThirdPartyIntegration_Expecter) HandleWebhook(ctx interface{}) *ThirdPartyIntegration_HandleWebhook_Call {
	return &ThirdPartyIntegration_HandleWebhook_Call{Call: _e.mock.On("HandleWebhook", ctx)}
}

func (_c *ThirdPartyIntegration_HandleWebhook_Call) Run(run func(ctx core.Context)) *ThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.Context
		if args[0] != nil {
			arg0 = args[0].(core.Context)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_HandleWebhook_Call) Return(err error) *ThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ThirdPartyIntegration_HandleWebhook_Call) RunAndReturn(run func(ctx core.Context) error) *ThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// HasAccessToExternalEntityProvider provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	ret := _mock.Called(ctx, externalEntityProviderID)

	if len(ret) == 0 {
		panic("no return value specified for HasAccessToExternalEntityProvider")
	}

	var r0 bool
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(core.Context, string) (bool, error)); ok {
		return returnFunc(ctx, externalEntityProviderID)
	}
	if returnFunc, ok := ret.Get(0).(func(core.Context, string) bool); ok {
		r0 = returnFunc(ctx, externalEntityProviderID)
	} else {
		r0 = ret.Get(0).(bool)
	}
	if returnFunc, ok := ret.Get(1).(func(core.Context, string) error); ok {
		r1 = returnFunc(ctx, externalEntityProviderID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasAccessToExternalEntityProvider'
type ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call struct {
	*mock.Call
}

// HasAccessToExternalEntityProvider is a helper method to define mock.On call
//   - ctx core.Context
//   - externalEntityProviderID string
func (_e *ThirdPartyIntegration_Expecter) HasAccessToExternalEntityProvider(ctx interface{}, externalEntityProviderID interface{}) *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call {
	return &ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call{Call: _e.mock.On("HasAccessToExternalEntityProvider", ctx, externalEntityProviderID)}
}

func (_c *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call) Run(run func(ctx core.Context, externalEntityProviderID string)) *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.Context
		if args[0] != nil {
			arg0 = args[0].(core.Context)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call) Return(b bool, err error) *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call {
	_c.Call.Return(b, err)
	return _c
}

func (_c *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call) RunAndReturn(run func(ctx core.Context, externalEntityProviderID string) (bool, error)) *ThirdPartyIntegration_HasAccessToExternalEntityProvider_Call {
	_c.Call.Return(run)
	return _c
}

// ListGroups provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []core.Role, error) {
	ret := _mock.Called(ctx, userID, providerID)

	if len(ret) == 0 {
		panic("no return value specified for ListGroups")
	}

	var r0 []models.Project
	var r1 []core.Role
	var r2 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) ([]models.Project, []core.Role, error)); ok {
		return returnFunc(ctx, userID, providerID)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string) []models.Project); ok {
		r0 = returnFunc(ctx, userID, providerID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string) []core.Role); ok {
		r1 = returnFunc(ctx, userID, providerID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]core.Role)
		}
	}
	if returnFunc, ok := ret.Get(2).(func(context.Context, string, string) error); ok {
		r2 = returnFunc(ctx, userID, providerID)
	} else {
		r2 = ret.Error(2)
	}
	return r0, r1, r2
}

// ThirdPartyIntegration_ListGroups_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListGroups'
type ThirdPartyIntegration_ListGroups_Call struct {
	*mock.Call
}

// ListGroups is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
//   - providerID string
func (_e *ThirdPartyIntegration_Expecter) ListGroups(ctx interface{}, userID interface{}, providerID interface{}) *ThirdPartyIntegration_ListGroups_Call {
	return &ThirdPartyIntegration_ListGroups_Call{Call: _e.mock.On("ListGroups", ctx, userID, providerID)}
}

func (_c *ThirdPartyIntegration_ListGroups_Call) Run(run func(ctx context.Context, userID string, providerID string)) *ThirdPartyIntegration_ListGroups_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_ListGroups_Call) Return(projects []models.Project, roles []core.Role, err error) *ThirdPartyIntegration_ListGroups_Call {
	_c.Call.Return(projects, roles, err)
	return _c
}

func (_c *ThirdPartyIntegration_ListGroups_Call) RunAndReturn(run func(ctx context.Context, userID string, providerID string) ([]models.Project, []core.Role, error)) *ThirdPartyIntegration_ListGroups_Call {
	_c.Call.Return(run)
	return _c
}

// ListOrgs provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	ret := _mock.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListOrgs")
	}

	var r0 []models.Org
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(core.Context) ([]models.Org, error)); ok {
		return returnFunc(ctx)
	}
	if returnFunc, ok := ret.Get(0).(func(core.Context) []models.Org); ok {
		r0 = returnFunc(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Org)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(core.Context) error); ok {
		r1 = returnFunc(ctx)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ThirdPartyIntegration_ListOrgs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListOrgs'
type ThirdPartyIntegration_ListOrgs_Call struct {
	*mock.Call
}

// ListOrgs is a helper method to define mock.On call
//   - ctx core.Context
func (_e *ThirdPartyIntegration_Expecter) ListOrgs(ctx interface{}) *ThirdPartyIntegration_ListOrgs_Call {
	return &ThirdPartyIntegration_ListOrgs_Call{Call: _e.mock.On("ListOrgs", ctx)}
}

func (_c *ThirdPartyIntegration_ListOrgs_Call) Run(run func(ctx core.Context)) *ThirdPartyIntegration_ListOrgs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.Context
		if args[0] != nil {
			arg0 = args[0].(core.Context)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_ListOrgs_Call) Return(orgs []models.Org, err error) *ThirdPartyIntegration_ListOrgs_Call {
	_c.Call.Return(orgs, err)
	return _c
}

func (_c *ThirdPartyIntegration_ListOrgs_Call) RunAndReturn(run func(ctx core.Context) ([]models.Org, error)) *ThirdPartyIntegration_ListOrgs_Call {
	_c.Call.Return(run)
	return _c
}

// ListProjects provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []core.Role, error) {
	ret := _mock.Called(ctx, userID, providerID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for ListProjects")
	}

	var r0 []models.Asset
	var r1 []core.Role
	var r2 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) ([]models.Asset, []core.Role, error)); ok {
		return returnFunc(ctx, userID, providerID, groupID)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) []models.Asset); ok {
		r0 = returnFunc(ctx, userID, providerID, groupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Asset)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string, string) []core.Role); ok {
		r1 = returnFunc(ctx, userID, providerID, groupID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]core.Role)
		}
	}
	if returnFunc, ok := ret.Get(2).(func(context.Context, string, string, string) error); ok {
		r2 = returnFunc(ctx, userID, providerID, groupID)
	} else {
		r2 = ret.Error(2)
	}
	return r0, r1, r2
}

// ThirdPartyIntegration_ListProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListProjects'
type ThirdPartyIntegration_ListProjects_Call struct {
	*mock.Call
}

// ListProjects is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
//   - providerID string
//   - groupID string
func (_e *ThirdPartyIntegration_Expecter) ListProjects(ctx interface{}, userID interface{}, providerID interface{}, groupID interface{}) *ThirdPartyIntegration_ListProjects_Call {
	return &ThirdPartyIntegration_ListProjects_Call{Call: _e.mock.On("ListProjects", ctx, userID, providerID, groupID)}
}

func (_c *ThirdPartyIntegration_ListProjects_Call) Run(run func(ctx context.Context, userID string, providerID string, groupID string)) *ThirdPartyIntegration_ListProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		var arg3 string
		if args[3] != nil {
			arg3 = args[3].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_ListProjects_Call) Return(assets []models.Asset, roles []core.Role, err error) *ThirdPartyIntegration_ListProjects_Call {
	_c.Call.Return(assets, roles, err)
	return _c
}

func (_c *ThirdPartyIntegration_ListProjects_Call) RunAndReturn(run func(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []core.Role, error)) *ThirdPartyIntegration_ListProjects_Call {
	_c.Call.Return(run)
	return _c
}

// ListRepositories provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	ret := _mock.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListRepositories")
	}

	var r0 []core.Repository
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(core.Context) ([]core.Repository, error)); ok {
		return returnFunc(ctx)
	}
	if returnFunc, ok := ret.Get(0).(func(core.Context) []core.Repository); ok {
		r0 = returnFunc(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.Repository)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(core.Context) error); ok {
		r1 = returnFunc(ctx)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ThirdPartyIntegration_ListRepositories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListRepositories'
type ThirdPartyIntegration_ListRepositories_Call struct {
	*mock.Call
}

// ListRepositories is a helper method to define mock.On call
//   - ctx core.Context
func (_e *ThirdPartyIntegration_Expecter) ListRepositories(ctx interface{}) *ThirdPartyIntegration_ListRepositories_Call {
	return &ThirdPartyIntegration_ListRepositories_Call{Call: _e.mock.On("ListRepositories", ctx)}
}

func (_c *ThirdPartyIntegration_ListRepositories_Call) Run(run func(ctx core.Context)) *ThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.Context
		if args[0] != nil {
			arg0 = args[0].(core.Context)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_ListRepositories_Call) Return(repositorys []core.Repository, err error) *ThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Return(repositorys, err)
	return _c
}

func (_c *ThirdPartyIntegration_ListRepositories_Call) RunAndReturn(run func(ctx core.Context) ([]core.Repository, error)) *ThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateIssue provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	ret := _mock.Called(ctx, asset, vuln)

	if len(ret) == 0 {
		panic("no return value specified for UpdateIssue")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, models.Asset, models.Vuln) error); ok {
		r0 = returnFunc(ctx, asset, vuln)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ThirdPartyIntegration_UpdateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateIssue'
type ThirdPartyIntegration_UpdateIssue_Call struct {
	*mock.Call
}

// UpdateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - asset models.Asset
//   - vuln models.Vuln
func (_e *ThirdPartyIntegration_Expecter) UpdateIssue(ctx interface{}, asset interface{}, vuln interface{}) *ThirdPartyIntegration_UpdateIssue_Call {
	return &ThirdPartyIntegration_UpdateIssue_Call{Call: _e.mock.On("UpdateIssue", ctx, asset, vuln)}
}

func (_c *ThirdPartyIntegration_UpdateIssue_Call) Run(run func(ctx context.Context, asset models.Asset, vuln models.Vuln)) *ThirdPartyIntegration_UpdateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 models.Asset
		if args[1] != nil {
			arg1 = args[1].(models.Asset)
		}
		var arg2 models.Vuln
		if args[2] != nil {
			arg2 = args[2].(models.Vuln)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_UpdateIssue_Call) Return(err error) *ThirdPartyIntegration_UpdateIssue_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ThirdPartyIntegration_UpdateIssue_Call) RunAndReturn(run func(ctx context.Context, asset models.Asset, vuln models.Vuln) error) *ThirdPartyIntegration_UpdateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// WantsToHandleWebhook provides a mock function for the type ThirdPartyIntegration
func (_mock *ThirdPartyIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	ret := _mock.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for WantsToHandleWebhook")
	}

	var r0 bool
	if returnFunc, ok := ret.Get(0).(func(core.Context) bool); ok {
		r0 = returnFunc(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}
	return r0
}

// ThirdPartyIntegration_WantsToHandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WantsToHandleWebhook'
type ThirdPartyIntegration_WantsToHandleWebhook_Call struct {
	*mock.Call
}

// WantsToHandleWebhook is a helper method to define mock.On call
//   - ctx core.Context
func (_e *ThirdPartyIntegration_Expecter) WantsToHandleWebhook(ctx interface{}) *ThirdPartyIntegration_WantsToHandleWebhook_Call {
	return &ThirdPartyIntegration_WantsToHandleWebhook_Call{Call: _e.mock.On("WantsToHandleWebhook", ctx)}
}

func (_c *ThirdPartyIntegration_WantsToHandleWebhook_Call) Run(run func(ctx core.Context)) *ThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.Context
		if args[0] != nil {
			arg0 = args[0].(core.Context)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ThirdPartyIntegration_WantsToHandleWebhook_Call) Return(b bool) *ThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Return(b)
	return _c
}

func (_c *ThirdPartyIntegration_WantsToHandleWebhook_Call) RunAndReturn(run func(ctx core.Context) bool) *ThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}
