// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// IntotoAccessControl is an autogenerated mock type for the accessControl type
type IntotoAccessControl struct {
	mock.Mock
}

type IntotoAccessControl_Expecter struct {
	mock *mock.Mock
}

func (_m *IntotoAccessControl) EXPECT() *IntotoAccessControl_Expecter {
	return &IntotoAccessControl_Expecter{mock: &_m.Mock}
}

// GetAllMembersOfProject provides a mock function with given fields: organizationID, projectID
func (_m *IntotoAccessControl) GetAllMembersOfProject(organizationID string, projectID string) ([]string, error) {
	ret := _m.Called(organizationID, projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllMembersOfProject")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) ([]string, error)); ok {
		return rf(organizationID, projectID)
	}
	if rf, ok := ret.Get(0).(func(string, string) []string); ok {
		r0 = rf(organizationID, projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(organizationID, projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntotoAccessControl_GetAllMembersOfProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllMembersOfProject'
type IntotoAccessControl_GetAllMembersOfProject_Call struct {
	*mock.Call
}

// GetAllMembersOfProject is a helper method to define mock.On call
//   - organizationID string
//   - projectID string
func (_e *IntotoAccessControl_Expecter) GetAllMembersOfProject(organizationID interface{}, projectID interface{}) *IntotoAccessControl_GetAllMembersOfProject_Call {
	return &IntotoAccessControl_GetAllMembersOfProject_Call{Call: _e.mock.On("GetAllMembersOfProject", organizationID, projectID)}
}

func (_c *IntotoAccessControl_GetAllMembersOfProject_Call) Run(run func(organizationID string, projectID string)) *IntotoAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *IntotoAccessControl_GetAllMembersOfProject_Call) Return(_a0 []string, _a1 error) *IntotoAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoAccessControl_GetAllMembersOfProject_Call) RunAndReturn(run func(string, string) ([]string, error)) *IntotoAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntotoAccessControl creates a new instance of IntotoAccessControl. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntotoAccessControl(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntotoAccessControl {
	mock := &IntotoAccessControl{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
