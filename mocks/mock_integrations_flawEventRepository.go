// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// IntegrationsFlawEventRepository is an autogenerated mock type for the flawEventRepository type
type IntegrationsFlawEventRepository struct {
	mock.Mock
}

type IntegrationsFlawEventRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsFlawEventRepository) EXPECT() *IntegrationsFlawEventRepository_Expecter {
	return &IntegrationsFlawEventRepository_Expecter{mock: &_m.Mock}
}

// Save provides a mock function with given fields: db, event
func (_m *IntegrationsFlawEventRepository) Save(db *gorm.DB, event *models.FlawEvent) error {
	ret := _m.Called(db, event)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.FlawEvent) error); ok {
		r0 = rf(db, event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsFlawEventRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type IntegrationsFlawEventRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - event *models.FlawEvent
func (_e *IntegrationsFlawEventRepository_Expecter) Save(db interface{}, event interface{}) *IntegrationsFlawEventRepository_Save_Call {
	return &IntegrationsFlawEventRepository_Save_Call{Call: _e.mock.On("Save", db, event)}
}

func (_c *IntegrationsFlawEventRepository_Save_Call) Run(run func(db *gorm.DB, event *models.FlawEvent)) *IntegrationsFlawEventRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.FlawEvent))
	})
	return _c
}

func (_c *IntegrationsFlawEventRepository_Save_Call) Return(_a0 error) *IntegrationsFlawEventRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsFlawEventRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.FlawEvent) error) *IntegrationsFlawEventRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsFlawEventRepository creates a new instance of IntegrationsFlawEventRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsFlawEventRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsFlawEventRepository {
	mock := &IntegrationsFlawEventRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}