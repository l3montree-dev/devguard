// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// CoreConfigService is an autogenerated mock type for the ConfigService type
type CoreConfigService struct {
	mock.Mock
}

type CoreConfigService_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreConfigService) EXPECT() *CoreConfigService_Expecter {
	return &CoreConfigService_Expecter{mock: &_m.Mock}
}

// GetJSONConfig provides a mock function with given fields: key, v
func (_m *CoreConfigService) GetJSONConfig(key string, v interface{}) error {
	ret := _m.Called(key, v)

	if len(ret) == 0 {
		panic("no return value specified for GetJSONConfig")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, interface{}) error); ok {
		r0 = rf(key, v)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreConfigService_GetJSONConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetJSONConfig'
type CoreConfigService_GetJSONConfig_Call struct {
	*mock.Call
}

// GetJSONConfig is a helper method to define mock.On call
//   - key string
//   - v interface{}
func (_e *CoreConfigService_Expecter) GetJSONConfig(key interface{}, v interface{}) *CoreConfigService_GetJSONConfig_Call {
	return &CoreConfigService_GetJSONConfig_Call{Call: _e.mock.On("GetJSONConfig", key, v)}
}

func (_c *CoreConfigService_GetJSONConfig_Call) Run(run func(key string, v interface{})) *CoreConfigService_GetJSONConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(interface{}))
	})
	return _c
}

func (_c *CoreConfigService_GetJSONConfig_Call) Return(_a0 error) *CoreConfigService_GetJSONConfig_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreConfigService_GetJSONConfig_Call) RunAndReturn(run func(string, interface{}) error) *CoreConfigService_GetJSONConfig_Call {
	_c.Call.Return(run)
	return _c
}

// SetJSONConfig provides a mock function with given fields: key, v
func (_m *CoreConfigService) SetJSONConfig(key string, v interface{}) error {
	ret := _m.Called(key, v)

	if len(ret) == 0 {
		panic("no return value specified for SetJSONConfig")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, interface{}) error); ok {
		r0 = rf(key, v)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreConfigService_SetJSONConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetJSONConfig'
type CoreConfigService_SetJSONConfig_Call struct {
	*mock.Call
}

// SetJSONConfig is a helper method to define mock.On call
//   - key string
//   - v interface{}
func (_e *CoreConfigService_Expecter) SetJSONConfig(key interface{}, v interface{}) *CoreConfigService_SetJSONConfig_Call {
	return &CoreConfigService_SetJSONConfig_Call{Call: _e.mock.On("SetJSONConfig", key, v)}
}

func (_c *CoreConfigService_SetJSONConfig_Call) Run(run func(key string, v interface{})) *CoreConfigService_SetJSONConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(interface{}))
	})
	return _c
}

func (_c *CoreConfigService_SetJSONConfig_Call) Return(_a0 error) *CoreConfigService_SetJSONConfig_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreConfigService_SetJSONConfig_Call) RunAndReturn(run func(string, interface{}) error) *CoreConfigService_SetJSONConfig_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreConfigService creates a new instance of CoreConfigService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreConfigService(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreConfigService {
	mock := &CoreConfigService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
