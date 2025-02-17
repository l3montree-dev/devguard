// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// IntegrationsGithubAppInstallationRepository is an autogenerated mock type for the githubAppInstallationRepository type
type IntegrationsGithubAppInstallationRepository struct {
	mock.Mock
}

type IntegrationsGithubAppInstallationRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsGithubAppInstallationRepository) EXPECT() *IntegrationsGithubAppInstallationRepository_Expecter {
	return &IntegrationsGithubAppInstallationRepository_Expecter{mock: &_m.Mock}
}

// Delete provides a mock function with given fields: tx, installationID
func (_m *IntegrationsGithubAppInstallationRepository) Delete(tx *gorm.DB, installationID int) error {
	ret := _m.Called(tx, installationID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, int) error); ok {
		r0 = rf(tx, installationID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsGithubAppInstallationRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type IntegrationsGithubAppInstallationRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - installationID int
func (_e *IntegrationsGithubAppInstallationRepository_Expecter) Delete(tx interface{}, installationID interface{}) *IntegrationsGithubAppInstallationRepository_Delete_Call {
	return &IntegrationsGithubAppInstallationRepository_Delete_Call{Call: _e.mock.On("Delete", tx, installationID)}
}

func (_c *IntegrationsGithubAppInstallationRepository_Delete_Call) Run(run func(tx *gorm.DB, installationID int)) *IntegrationsGithubAppInstallationRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(int))
	})
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Delete_Call) Return(_a0 error) *IntegrationsGithubAppInstallationRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, int) error) *IntegrationsGithubAppInstallationRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// FindByOrganizationId provides a mock function with given fields: orgID
func (_m *IntegrationsGithubAppInstallationRepository) FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error) {
	ret := _m.Called(orgID)

	if len(ret) == 0 {
		panic("no return value specified for FindByOrganizationId")
	}

	var r0 []models.GithubAppInstallation
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.GithubAppInstallation, error)); ok {
		return rf(orgID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.GithubAppInstallation); ok {
		r0 = rf(orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.GithubAppInstallation)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByOrganizationId'
type IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call struct {
	*mock.Call
}

// FindByOrganizationId is a helper method to define mock.On call
//   - orgID uuid.UUID
func (_e *IntegrationsGithubAppInstallationRepository_Expecter) FindByOrganizationId(orgID interface{}) *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call {
	return &IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call{Call: _e.mock.On("FindByOrganizationId", orgID)}
}

func (_c *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call) Run(run func(orgID uuid.UUID)) *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call) Return(_a0 []models.GithubAppInstallation, _a1 error) *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call) RunAndReturn(run func(uuid.UUID) ([]models.GithubAppInstallation, error)) *IntegrationsGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: installationID
func (_m *IntegrationsGithubAppInstallationRepository) Read(installationID int) (models.GithubAppInstallation, error) {
	ret := _m.Called(installationID)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.GithubAppInstallation
	var r1 error
	if rf, ok := ret.Get(0).(func(int) (models.GithubAppInstallation, error)); ok {
		return rf(installationID)
	}
	if rf, ok := ret.Get(0).(func(int) models.GithubAppInstallation); ok {
		r0 = rf(installationID)
	} else {
		r0 = ret.Get(0).(models.GithubAppInstallation)
	}

	if rf, ok := ret.Get(1).(func(int) error); ok {
		r1 = rf(installationID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsGithubAppInstallationRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type IntegrationsGithubAppInstallationRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - installationID int
func (_e *IntegrationsGithubAppInstallationRepository_Expecter) Read(installationID interface{}) *IntegrationsGithubAppInstallationRepository_Read_Call {
	return &IntegrationsGithubAppInstallationRepository_Read_Call{Call: _e.mock.On("Read", installationID)}
}

func (_c *IntegrationsGithubAppInstallationRepository_Read_Call) Run(run func(installationID int)) *IntegrationsGithubAppInstallationRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Read_Call) Return(_a0 models.GithubAppInstallation, _a1 error) *IntegrationsGithubAppInstallationRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Read_Call) RunAndReturn(run func(int) (models.GithubAppInstallation, error)) *IntegrationsGithubAppInstallationRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, model
func (_m *IntegrationsGithubAppInstallationRepository) Save(tx *gorm.DB, model *models.GithubAppInstallation) error {
	ret := _m.Called(tx, model)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.GithubAppInstallation) error); ok {
		r0 = rf(tx, model)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsGithubAppInstallationRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type IntegrationsGithubAppInstallationRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - model *models.GithubAppInstallation
func (_e *IntegrationsGithubAppInstallationRepository_Expecter) Save(tx interface{}, model interface{}) *IntegrationsGithubAppInstallationRepository_Save_Call {
	return &IntegrationsGithubAppInstallationRepository_Save_Call{Call: _e.mock.On("Save", tx, model)}
}

func (_c *IntegrationsGithubAppInstallationRepository_Save_Call) Run(run func(tx *gorm.DB, model *models.GithubAppInstallation)) *IntegrationsGithubAppInstallationRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.GithubAppInstallation))
	})
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Save_Call) Return(_a0 error) *IntegrationsGithubAppInstallationRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsGithubAppInstallationRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.GithubAppInstallation) error) *IntegrationsGithubAppInstallationRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsGithubAppInstallationRepository creates a new instance of IntegrationsGithubAppInstallationRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsGithubAppInstallationRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsGithubAppInstallationRepository {
	mock := &IntegrationsGithubAppInstallationRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
