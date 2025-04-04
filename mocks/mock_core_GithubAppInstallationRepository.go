// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// CoreGithubAppInstallationRepository is an autogenerated mock type for the GithubAppInstallationRepository type
type CoreGithubAppInstallationRepository struct {
	mock.Mock
}

type CoreGithubAppInstallationRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreGithubAppInstallationRepository) EXPECT() *CoreGithubAppInstallationRepository_Expecter {
	return &CoreGithubAppInstallationRepository_Expecter{mock: &_m.Mock}
}

// Delete provides a mock function with given fields: tx, installationID
func (_m *CoreGithubAppInstallationRepository) Delete(tx *gorm.DB, installationID int) error {
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

// CoreGithubAppInstallationRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type CoreGithubAppInstallationRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - installationID int
func (_e *CoreGithubAppInstallationRepository_Expecter) Delete(tx interface{}, installationID interface{}) *CoreGithubAppInstallationRepository_Delete_Call {
	return &CoreGithubAppInstallationRepository_Delete_Call{Call: _e.mock.On("Delete", tx, installationID)}
}

func (_c *CoreGithubAppInstallationRepository_Delete_Call) Run(run func(tx *gorm.DB, installationID int)) *CoreGithubAppInstallationRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(int))
	})
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Delete_Call) Return(_a0 error) *CoreGithubAppInstallationRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, int) error) *CoreGithubAppInstallationRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// FindByOrganizationId provides a mock function with given fields: orgID
func (_m *CoreGithubAppInstallationRepository) FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error) {
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

// CoreGithubAppInstallationRepository_FindByOrganizationId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByOrganizationId'
type CoreGithubAppInstallationRepository_FindByOrganizationId_Call struct {
	*mock.Call
}

// FindByOrganizationId is a helper method to define mock.On call
//   - orgID uuid.UUID
func (_e *CoreGithubAppInstallationRepository_Expecter) FindByOrganizationId(orgID interface{}) *CoreGithubAppInstallationRepository_FindByOrganizationId_Call {
	return &CoreGithubAppInstallationRepository_FindByOrganizationId_Call{Call: _e.mock.On("FindByOrganizationId", orgID)}
}

func (_c *CoreGithubAppInstallationRepository_FindByOrganizationId_Call) Run(run func(orgID uuid.UUID)) *CoreGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *CoreGithubAppInstallationRepository_FindByOrganizationId_Call) Return(_a0 []models.GithubAppInstallation, _a1 error) *CoreGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreGithubAppInstallationRepository_FindByOrganizationId_Call) RunAndReturn(run func(uuid.UUID) ([]models.GithubAppInstallation, error)) *CoreGithubAppInstallationRepository_FindByOrganizationId_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: installationID
func (_m *CoreGithubAppInstallationRepository) Read(installationID int) (models.GithubAppInstallation, error) {
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

// CoreGithubAppInstallationRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type CoreGithubAppInstallationRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - installationID int
func (_e *CoreGithubAppInstallationRepository_Expecter) Read(installationID interface{}) *CoreGithubAppInstallationRepository_Read_Call {
	return &CoreGithubAppInstallationRepository_Read_Call{Call: _e.mock.On("Read", installationID)}
}

func (_c *CoreGithubAppInstallationRepository_Read_Call) Run(run func(installationID int)) *CoreGithubAppInstallationRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Read_Call) Return(_a0 models.GithubAppInstallation, _a1 error) *CoreGithubAppInstallationRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Read_Call) RunAndReturn(run func(int) (models.GithubAppInstallation, error)) *CoreGithubAppInstallationRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, model
func (_m *CoreGithubAppInstallationRepository) Save(tx *gorm.DB, model *models.GithubAppInstallation) error {
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

// CoreGithubAppInstallationRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type CoreGithubAppInstallationRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - model *models.GithubAppInstallation
func (_e *CoreGithubAppInstallationRepository_Expecter) Save(tx interface{}, model interface{}) *CoreGithubAppInstallationRepository_Save_Call {
	return &CoreGithubAppInstallationRepository_Save_Call{Call: _e.mock.On("Save", tx, model)}
}

func (_c *CoreGithubAppInstallationRepository_Save_Call) Run(run func(tx *gorm.DB, model *models.GithubAppInstallation)) *CoreGithubAppInstallationRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.GithubAppInstallation))
	})
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Save_Call) Return(_a0 error) *CoreGithubAppInstallationRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreGithubAppInstallationRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.GithubAppInstallation) error) *CoreGithubAppInstallationRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreGithubAppInstallationRepository creates a new instance of CoreGithubAppInstallationRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreGithubAppInstallationRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreGithubAppInstallationRepository {
	mock := &CoreGithubAppInstallationRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
