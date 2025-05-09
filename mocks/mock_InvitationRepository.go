// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// InvitationRepository is an autogenerated mock type for the InvitationRepository type
type InvitationRepository struct {
	mock.Mock
}

type InvitationRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *InvitationRepository) EXPECT() *InvitationRepository_Expecter {
	return &InvitationRepository_Expecter{mock: &_m.Mock}
}

// Delete provides a mock function with given fields: tx, id
func (_m *InvitationRepository) Delete(tx *gorm.DB, id uuid.UUID) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InvitationRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type InvitationRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *InvitationRepository_Expecter) Delete(tx interface{}, id interface{}) *InvitationRepository_Delete_Call {
	return &InvitationRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *InvitationRepository_Delete_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *InvitationRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *InvitationRepository_Delete_Call) Return(_a0 error) *InvitationRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *InvitationRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *InvitationRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// FindByCode provides a mock function with given fields: code
func (_m *InvitationRepository) FindByCode(code string) (models.Invitation, error) {
	ret := _m.Called(code)

	if len(ret) == 0 {
		panic("no return value specified for FindByCode")
	}

	var r0 models.Invitation
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.Invitation, error)); ok {
		return rf(code)
	}
	if rf, ok := ret.Get(0).(func(string) models.Invitation); ok {
		r0 = rf(code)
	} else {
		r0 = ret.Get(0).(models.Invitation)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(code)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InvitationRepository_FindByCode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByCode'
type InvitationRepository_FindByCode_Call struct {
	*mock.Call
}

// FindByCode is a helper method to define mock.On call
//   - code string
func (_e *InvitationRepository_Expecter) FindByCode(code interface{}) *InvitationRepository_FindByCode_Call {
	return &InvitationRepository_FindByCode_Call{Call: _e.mock.On("FindByCode", code)}
}

func (_c *InvitationRepository_FindByCode_Call) Run(run func(code string)) *InvitationRepository_FindByCode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *InvitationRepository_FindByCode_Call) Return(_a0 models.Invitation, _a1 error) *InvitationRepository_FindByCode_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *InvitationRepository_FindByCode_Call) RunAndReturn(run func(string) (models.Invitation, error)) *InvitationRepository_FindByCode_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, invitation
func (_m *InvitationRepository) Save(tx *gorm.DB, invitation *models.Invitation) error {
	ret := _m.Called(tx, invitation)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Invitation) error); ok {
		r0 = rf(tx, invitation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InvitationRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type InvitationRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - invitation *models.Invitation
func (_e *InvitationRepository_Expecter) Save(tx interface{}, invitation interface{}) *InvitationRepository_Save_Call {
	return &InvitationRepository_Save_Call{Call: _e.mock.On("Save", tx, invitation)}
}

func (_c *InvitationRepository_Save_Call) Run(run func(tx *gorm.DB, invitation *models.Invitation)) *InvitationRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Invitation))
	})
	return _c
}

func (_c *InvitationRepository_Save_Call) Return(_a0 error) *InvitationRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *InvitationRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Invitation) error) *InvitationRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewInvitationRepository creates a new instance of InvitationRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewInvitationRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *InvitationRepository {
	mock := &InvitationRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
