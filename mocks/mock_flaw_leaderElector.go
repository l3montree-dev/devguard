// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// DependencyVulnLeaderElector is an autogenerated mock type for the leaderElector type
type DependencyVulnLeaderElector struct {
	mock.Mock
}

type DependencyVulnLeaderElector_Expecter struct {
	mock *mock.Mock
}

func (_m *DependencyVulnLeaderElector) EXPECT() *DependencyVulnLeaderElector_Expecter {
	return &DependencyVulnLeaderElector_Expecter{mock: &_m.Mock}
}

// IfLeader provides a mock function with given fields: ctx, fn
func (_m *DependencyVulnLeaderElector) IfLeader(ctx context.Context, fn func() error) {
	_m.Called(ctx, fn)
}

// DependencyVulnLeaderElector_IfLeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IfLeader'
type DependencyVulnLeaderElector_IfLeader_Call struct {
	*mock.Call
}

// IfLeader is a helper method to define mock.On call
//   - ctx context.Context
//   - fn func() error
func (_e *DependencyVulnLeaderElector_Expecter) IfLeader(ctx interface{}, fn interface{}) *DependencyVulnLeaderElector_IfLeader_Call {
	return &DependencyVulnLeaderElector_IfLeader_Call{Call: _e.mock.On("IfLeader", ctx, fn)}
}

func (_c *DependencyVulnLeaderElector_IfLeader_Call) Run(run func(ctx context.Context, fn func() error)) *DependencyVulnLeaderElector_IfLeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(func() error))
	})
	return _c
}

func (_c *DependencyVulnLeaderElector_IfLeader_Call) Return() *DependencyVulnLeaderElector_IfLeader_Call {
	_c.Call.Return()
	return _c
}

func (_c *DependencyVulnLeaderElector_IfLeader_Call) RunAndReturn(run func(context.Context, func() error)) *DependencyVulnLeaderElector_IfLeader_Call {
	_c.Run(run)
	return _c
}

// NewDependencyVulnLeaderElector creates a new instance of DependencyVulnLeaderElector. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDependencyVulnLeaderElector(t interface {
	mock.TestingT
	Cleanup(func())
}) *DependencyVulnLeaderElector {
	mock := &DependencyVulnLeaderElector{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
