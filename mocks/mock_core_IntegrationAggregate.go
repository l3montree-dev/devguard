// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"
	echo "github.com/labstack/echo/v4"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// CoreIntegrationAggregate is an autogenerated mock type for the IntegrationAggregate type
type CoreIntegrationAggregate struct {
	mock.Mock
}

type CoreIntegrationAggregate_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreIntegrationAggregate) EXPECT() *CoreIntegrationAggregate_Expecter {
	return &CoreIntegrationAggregate_Expecter{mock: &_m.Mock}
}

// GetID provides a mock function with given fields:
func (_m *CoreIntegrationAggregate) GetID() core.IntegrationID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetID")
	}

	var r0 core.IntegrationID
	if rf, ok := ret.Get(0).(func() core.IntegrationID); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(core.IntegrationID)
	}

	return r0
}

// CoreIntegrationAggregate_GetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetID'
type CoreIntegrationAggregate_GetID_Call struct {
	*mock.Call
}

// GetID is a helper method to define mock.On call
func (_e *CoreIntegrationAggregate_Expecter) GetID() *CoreIntegrationAggregate_GetID_Call {
	return &CoreIntegrationAggregate_GetID_Call{Call: _e.mock.On("GetID")}
}

func (_c *CoreIntegrationAggregate_GetID_Call) Run(run func()) *CoreIntegrationAggregate_GetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreIntegrationAggregate_GetID_Call) Return(_a0 core.IntegrationID) *CoreIntegrationAggregate_GetID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_GetID_Call) RunAndReturn(run func() core.IntegrationID) *CoreIntegrationAggregate_GetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetIntegration provides a mock function with given fields: id
func (_m *CoreIntegrationAggregate) GetIntegration(id core.IntegrationID) core.ThirdPartyIntegration {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for GetIntegration")
	}

	var r0 core.ThirdPartyIntegration
	if rf, ok := ret.Get(0).(func(core.IntegrationID) core.ThirdPartyIntegration); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(core.ThirdPartyIntegration)
		}
	}

	return r0
}

// CoreIntegrationAggregate_GetIntegration_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetIntegration'
type CoreIntegrationAggregate_GetIntegration_Call struct {
	*mock.Call
}

// GetIntegration is a helper method to define mock.On call
//   - id core.IntegrationID
func (_e *CoreIntegrationAggregate_Expecter) GetIntegration(id interface{}) *CoreIntegrationAggregate_GetIntegration_Call {
	return &CoreIntegrationAggregate_GetIntegration_Call{Call: _e.mock.On("GetIntegration", id)}
}

func (_c *CoreIntegrationAggregate_GetIntegration_Call) Run(run func(id core.IntegrationID)) *CoreIntegrationAggregate_GetIntegration_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.IntegrationID))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_GetIntegration_Call) Return(_a0 core.ThirdPartyIntegration) *CoreIntegrationAggregate_GetIntegration_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_GetIntegration_Call) RunAndReturn(run func(core.IntegrationID) core.ThirdPartyIntegration) *CoreIntegrationAggregate_GetIntegration_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function with given fields: org
func (_m *CoreIntegrationAggregate) GetUsers(org models.Org) []core.User {
	ret := _m.Called(org)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []core.User
	if rf, ok := ret.Get(0).(func(models.Org) []core.User); ok {
		r0 = rf(org)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.User)
		}
	}

	return r0
}

// CoreIntegrationAggregate_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type CoreIntegrationAggregate_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - org models.Org
func (_e *CoreIntegrationAggregate_Expecter) GetUsers(org interface{}) *CoreIntegrationAggregate_GetUsers_Call {
	return &CoreIntegrationAggregate_GetUsers_Call{Call: _e.mock.On("GetUsers", org)}
}

func (_c *CoreIntegrationAggregate_GetUsers_Call) Run(run func(org models.Org)) *CoreIntegrationAggregate_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Org))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_GetUsers_Call) Return(_a0 []core.User) *CoreIntegrationAggregate_GetUsers_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_GetUsers_Call) RunAndReturn(run func(models.Org) []core.User) *CoreIntegrationAggregate_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

// HandleEvent provides a mock function with given fields: event
func (_m *CoreIntegrationAggregate) HandleEvent(event interface{}) error {
	ret := _m.Called(event)

	if len(ret) == 0 {
		panic("no return value specified for HandleEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreIntegrationAggregate_HandleEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleEvent'
type CoreIntegrationAggregate_HandleEvent_Call struct {
	*mock.Call
}

// HandleEvent is a helper method to define mock.On call
//   - event interface{}
func (_e *CoreIntegrationAggregate_Expecter) HandleEvent(event interface{}) *CoreIntegrationAggregate_HandleEvent_Call {
	return &CoreIntegrationAggregate_HandleEvent_Call{Call: _e.mock.On("HandleEvent", event)}
}

func (_c *CoreIntegrationAggregate_HandleEvent_Call) Run(run func(event interface{})) *CoreIntegrationAggregate_HandleEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_HandleEvent_Call) Return(_a0 error) *CoreIntegrationAggregate_HandleEvent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_HandleEvent_Call) RunAndReturn(run func(interface{}) error) *CoreIntegrationAggregate_HandleEvent_Call {
	_c.Call.Return(run)
	return _c
}

// HandleWebhook provides a mock function with given fields: ctx
func (_m *CoreIntegrationAggregate) HandleWebhook(ctx echo.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for HandleWebhook")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(echo.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreIntegrationAggregate_HandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleWebhook'
type CoreIntegrationAggregate_HandleWebhook_Call struct {
	*mock.Call
}

// HandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreIntegrationAggregate_Expecter) HandleWebhook(ctx interface{}) *CoreIntegrationAggregate_HandleWebhook_Call {
	return &CoreIntegrationAggregate_HandleWebhook_Call{Call: _e.mock.On("HandleWebhook", ctx)}
}

func (_c *CoreIntegrationAggregate_HandleWebhook_Call) Run(run func(ctx echo.Context)) *CoreIntegrationAggregate_HandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_HandleWebhook_Call) Return(_a0 error) *CoreIntegrationAggregate_HandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_HandleWebhook_Call) RunAndReturn(run func(echo.Context) error) *CoreIntegrationAggregate_HandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// IntegrationEnabled provides a mock function with given fields: ctx
func (_m *CoreIntegrationAggregate) IntegrationEnabled(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for IntegrationEnabled")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// CoreIntegrationAggregate_IntegrationEnabled_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IntegrationEnabled'
type CoreIntegrationAggregate_IntegrationEnabled_Call struct {
	*mock.Call
}

// IntegrationEnabled is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreIntegrationAggregate_Expecter) IntegrationEnabled(ctx interface{}) *CoreIntegrationAggregate_IntegrationEnabled_Call {
	return &CoreIntegrationAggregate_IntegrationEnabled_Call{Call: _e.mock.On("IntegrationEnabled", ctx)}
}

func (_c *CoreIntegrationAggregate_IntegrationEnabled_Call) Run(run func(ctx echo.Context)) *CoreIntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_IntegrationEnabled_Call) Return(_a0 bool) *CoreIntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_IntegrationEnabled_Call) RunAndReturn(run func(echo.Context) bool) *CoreIntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Return(run)
	return _c
}

// ListRepositories provides a mock function with given fields: ctx
func (_m *CoreIntegrationAggregate) ListRepositories(ctx echo.Context) ([]core.Repository, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListRepositories")
	}

	var r0 []core.Repository
	var r1 error
	if rf, ok := ret.Get(0).(func(echo.Context) ([]core.Repository, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(echo.Context) []core.Repository); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(echo.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreIntegrationAggregate_ListRepositories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListRepositories'
type CoreIntegrationAggregate_ListRepositories_Call struct {
	*mock.Call
}

// ListRepositories is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreIntegrationAggregate_Expecter) ListRepositories(ctx interface{}) *CoreIntegrationAggregate_ListRepositories_Call {
	return &CoreIntegrationAggregate_ListRepositories_Call{Call: _e.mock.On("ListRepositories", ctx)}
}

func (_c *CoreIntegrationAggregate_ListRepositories_Call) Run(run func(ctx echo.Context)) *CoreIntegrationAggregate_ListRepositories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_ListRepositories_Call) Return(_a0 []core.Repository, _a1 error) *CoreIntegrationAggregate_ListRepositories_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreIntegrationAggregate_ListRepositories_Call) RunAndReturn(run func(echo.Context) ([]core.Repository, error)) *CoreIntegrationAggregate_ListRepositories_Call {
	_c.Call.Return(run)
	return _c
}

// WantsToHandleWebhook provides a mock function with given fields: ctx
func (_m *CoreIntegrationAggregate) WantsToHandleWebhook(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for WantsToHandleWebhook")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// CoreIntegrationAggregate_WantsToHandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WantsToHandleWebhook'
type CoreIntegrationAggregate_WantsToHandleWebhook_Call struct {
	*mock.Call
}

// WantsToHandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreIntegrationAggregate_Expecter) WantsToHandleWebhook(ctx interface{}) *CoreIntegrationAggregate_WantsToHandleWebhook_Call {
	return &CoreIntegrationAggregate_WantsToHandleWebhook_Call{Call: _e.mock.On("WantsToHandleWebhook", ctx)}
}

func (_c *CoreIntegrationAggregate_WantsToHandleWebhook_Call) Run(run func(ctx echo.Context)) *CoreIntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreIntegrationAggregate_WantsToHandleWebhook_Call) Return(_a0 bool) *CoreIntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreIntegrationAggregate_WantsToHandleWebhook_Call) RunAndReturn(run func(echo.Context) bool) *CoreIntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreIntegrationAggregate creates a new instance of CoreIntegrationAggregate. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreIntegrationAggregate(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreIntegrationAggregate {
	mock := &CoreIntegrationAggregate{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}