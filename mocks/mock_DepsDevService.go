// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"context"

	"github.com/l3montree-dev/devguard/internal/common"
	mock "github.com/stretchr/testify/mock"
)

// NewDepsDevService creates a new instance of DepsDevService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDepsDevService(t interface {
	mock.TestingT
	Cleanup(func())
}) *DepsDevService {
	mock := &DepsDevService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// DepsDevService is an autogenerated mock type for the DepsDevService type
type DepsDevService struct {
	mock.Mock
}

type DepsDevService_Expecter struct {
	mock *mock.Mock
}

func (_m *DepsDevService) EXPECT() *DepsDevService_Expecter {
	return &DepsDevService_Expecter{mock: &_m.Mock}
}

// GetProject provides a mock function for the type DepsDevService
func (_mock *DepsDevService) GetProject(ctx context.Context, projectID string) (common.DepsDevProjectResponse, error) {
	ret := _mock.Called(ctx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetProject")
	}

	var r0 common.DepsDevProjectResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string) (common.DepsDevProjectResponse, error)); ok {
		return returnFunc(ctx, projectID)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string) common.DepsDevProjectResponse); ok {
		r0 = returnFunc(ctx, projectID)
	} else {
		r0 = ret.Get(0).(common.DepsDevProjectResponse)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = returnFunc(ctx, projectID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// DepsDevService_GetProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProject'
type DepsDevService_GetProject_Call struct {
	*mock.Call
}

// GetProject is a helper method to define mock.On call
//   - ctx context.Context
//   - projectID string
func (_e *DepsDevService_Expecter) GetProject(ctx interface{}, projectID interface{}) *DepsDevService_GetProject_Call {
	return &DepsDevService_GetProject_Call{Call: _e.mock.On("GetProject", ctx, projectID)}
}

func (_c *DepsDevService_GetProject_Call) Run(run func(ctx context.Context, projectID string)) *DepsDevService_GetProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
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

func (_c *DepsDevService_GetProject_Call) Return(depsDevProjectResponse common.DepsDevProjectResponse, err error) *DepsDevService_GetProject_Call {
	_c.Call.Return(depsDevProjectResponse, err)
	return _c
}

func (_c *DepsDevService_GetProject_Call) RunAndReturn(run func(ctx context.Context, projectID string) (common.DepsDevProjectResponse, error)) *DepsDevService_GetProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetVersion provides a mock function for the type DepsDevService
func (_mock *DepsDevService) GetVersion(ctx context.Context, ecosystem string, packageName string, version string) (common.DepsDevVersionResponse, error) {
	ret := _mock.Called(ctx, ecosystem, packageName, version)

	if len(ret) == 0 {
		panic("no return value specified for GetVersion")
	}

	var r0 common.DepsDevVersionResponse
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) (common.DepsDevVersionResponse, error)); ok {
		return returnFunc(ctx, ecosystem, packageName, version)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, string, string, string) common.DepsDevVersionResponse); ok {
		r0 = returnFunc(ctx, ecosystem, packageName, version)
	} else {
		r0 = ret.Get(0).(common.DepsDevVersionResponse)
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = returnFunc(ctx, ecosystem, packageName, version)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// DepsDevService_GetVersion_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetVersion'
type DepsDevService_GetVersion_Call struct {
	*mock.Call
}

// GetVersion is a helper method to define mock.On call
//   - ctx context.Context
//   - ecosystem string
//   - packageName string
//   - version string
func (_e *DepsDevService_Expecter) GetVersion(ctx interface{}, ecosystem interface{}, packageName interface{}, version interface{}) *DepsDevService_GetVersion_Call {
	return &DepsDevService_GetVersion_Call{Call: _e.mock.On("GetVersion", ctx, ecosystem, packageName, version)}
}

func (_c *DepsDevService_GetVersion_Call) Run(run func(ctx context.Context, ecosystem string, packageName string, version string)) *DepsDevService_GetVersion_Call {
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

func (_c *DepsDevService_GetVersion_Call) Return(depsDevVersionResponse common.DepsDevVersionResponse, err error) *DepsDevService_GetVersion_Call {
	_c.Call.Return(depsDevVersionResponse, err)
	return _c
}

func (_c *DepsDevService_GetVersion_Call) RunAndReturn(run func(ctx context.Context, ecosystem string, packageName string, version string) (common.DepsDevVersionResponse, error)) *DepsDevService_GetVersion_Call {
	_c.Call.Return(run)
	return _c
}
