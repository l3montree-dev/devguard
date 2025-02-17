// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	uuid "github.com/google/uuid"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// IntotoPatRepository is an autogenerated mock type for the patRepository type
type IntotoPatRepository struct {
	mock.Mock
}

type IntotoPatRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntotoPatRepository) EXPECT() *IntotoPatRepository_Expecter {
	return &IntotoPatRepository_Expecter{mock: &_m.Mock}
}

// FindByUserIDs provides a mock function with given fields: userID
func (_m *IntotoPatRepository) FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error) {
	ret := _m.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for FindByUserIDs")
	}

	var r0 []models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]models.PAT, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []models.PAT); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntotoPatRepository_FindByUserIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByUserIDs'
type IntotoPatRepository_FindByUserIDs_Call struct {
	*mock.Call
}

// FindByUserIDs is a helper method to define mock.On call
//   - userID []uuid.UUID
func (_e *IntotoPatRepository_Expecter) FindByUserIDs(userID interface{}) *IntotoPatRepository_FindByUserIDs_Call {
	return &IntotoPatRepository_FindByUserIDs_Call{Call: _e.mock.On("FindByUserIDs", userID)}
}

func (_c *IntotoPatRepository_FindByUserIDs_Call) Run(run func(userID []uuid.UUID)) *IntotoPatRepository_FindByUserIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *IntotoPatRepository_FindByUserIDs_Call) Return(_a0 []models.PAT, _a1 error) *IntotoPatRepository_FindByUserIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoPatRepository_FindByUserIDs_Call) RunAndReturn(run func([]uuid.UUID) ([]models.PAT, error)) *IntotoPatRepository_FindByUserIDs_Call {
	_c.Call.Return(run)
	return _c
}

// GetByFingerprint provides a mock function with given fields: fingerprint
func (_m *IntotoPatRepository) GetByFingerprint(fingerprint string) (models.PAT, error) {
	ret := _m.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for GetByFingerprint")
	}

	var r0 models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.PAT, error)); ok {
		return rf(fingerprint)
	}
	if rf, ok := ret.Get(0).(func(string) models.PAT); ok {
		r0 = rf(fingerprint)
	} else {
		r0 = ret.Get(0).(models.PAT)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(fingerprint)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntotoPatRepository_GetByFingerprint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByFingerprint'
type IntotoPatRepository_GetByFingerprint_Call struct {
	*mock.Call
}

// GetByFingerprint is a helper method to define mock.On call
//   - fingerprint string
func (_e *IntotoPatRepository_Expecter) GetByFingerprint(fingerprint interface{}) *IntotoPatRepository_GetByFingerprint_Call {
	return &IntotoPatRepository_GetByFingerprint_Call{Call: _e.mock.On("GetByFingerprint", fingerprint)}
}

func (_c *IntotoPatRepository_GetByFingerprint_Call) Run(run func(fingerprint string)) *IntotoPatRepository_GetByFingerprint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *IntotoPatRepository_GetByFingerprint_Call) Return(_a0 models.PAT, _a1 error) *IntotoPatRepository_GetByFingerprint_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoPatRepository_GetByFingerprint_Call) RunAndReturn(run func(string) (models.PAT, error)) *IntotoPatRepository_GetByFingerprint_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntotoPatRepository creates a new instance of IntotoPatRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntotoPatRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntotoPatRepository {
	mock := &IntotoPatRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
