// Code generated by mockery v2.42.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/flawfix/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// AssetComponentRepository is an autogenerated mock type for the componentRepository type
type AssetComponentRepository struct {
	mock.Mock
}

type AssetComponentRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetComponentRepository) EXPECT() *AssetComponentRepository_Expecter {
	return &AssetComponentRepository_Expecter{mock: &_m.Mock}
}

// FindByPurl provides a mock function with given fields: tx, purl
func (_m *AssetComponentRepository) FindByPurl(tx *gorm.DB, purl string) (models.Component, error) {
	ret := _m.Called(tx, purl)

	if len(ret) == 0 {
		panic("no return value specified for FindByPurl")
	}

	var r0 models.Component
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) (models.Component, error)); ok {
		return rf(tx, purl)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) models.Component); ok {
		r0 = rf(tx, purl)
	} else {
		r0 = ret.Get(0).(models.Component)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string) error); ok {
		r1 = rf(tx, purl)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetComponentRepository_FindByPurl_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByPurl'
type AssetComponentRepository_FindByPurl_Call struct {
	*mock.Call
}

// FindByPurl is a helper method to define mock.On call
//   - tx *gorm.DB
//   - purl string
func (_e *AssetComponentRepository_Expecter) FindByPurl(tx interface{}, purl interface{}) *AssetComponentRepository_FindByPurl_Call {
	return &AssetComponentRepository_FindByPurl_Call{Call: _e.mock.On("FindByPurl", tx, purl)}
}

func (_c *AssetComponentRepository_FindByPurl_Call) Run(run func(tx *gorm.DB, purl string)) *AssetComponentRepository_FindByPurl_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *AssetComponentRepository_FindByPurl_Call) Return(_a0 models.Component, _a1 error) *AssetComponentRepository_FindByPurl_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetComponentRepository_FindByPurl_Call) RunAndReturn(run func(*gorm.DB, string) (models.Component, error)) *AssetComponentRepository_FindByPurl_Call {
	_c.Call.Return(run)
	return _c
}

// HandleStateDiff provides a mock function with given fields: tx, assetID, version, oldState, newState
func (_m *AssetComponentRepository) HandleStateDiff(tx *gorm.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error {
	ret := _m.Called(tx, assetID, version, oldState, newState)

	if len(ret) == 0 {
		panic("no return value specified for HandleStateDiff")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, string, []models.ComponentDependency, []models.ComponentDependency) error); ok {
		r0 = rf(tx, assetID, version, oldState, newState)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetComponentRepository_HandleStateDiff_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleStateDiff'
type AssetComponentRepository_HandleStateDiff_Call struct {
	*mock.Call
}

// HandleStateDiff is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
//   - version string
//   - oldState []models.ComponentDependency
//   - newState []models.ComponentDependency
func (_e *AssetComponentRepository_Expecter) HandleStateDiff(tx interface{}, assetID interface{}, version interface{}, oldState interface{}, newState interface{}) *AssetComponentRepository_HandleStateDiff_Call {
	return &AssetComponentRepository_HandleStateDiff_Call{Call: _e.mock.On("HandleStateDiff", tx, assetID, version, oldState, newState)}
}

func (_c *AssetComponentRepository_HandleStateDiff_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency)) *AssetComponentRepository_HandleStateDiff_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(string), args[3].([]models.ComponentDependency), args[4].([]models.ComponentDependency))
	})
	return _c
}

func (_c *AssetComponentRepository_HandleStateDiff_Call) Return(_a0 error) *AssetComponentRepository_HandleStateDiff_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetComponentRepository_HandleStateDiff_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, string, []models.ComponentDependency, []models.ComponentDependency) error) *AssetComponentRepository_HandleStateDiff_Call {
	_c.Call.Return(run)
	return _c
}

// LoadAssetComponents provides a mock function with given fields: tx, _a1, version
func (_m *AssetComponentRepository) LoadAssetComponents(tx *gorm.DB, _a1 models.Asset, version string) ([]models.ComponentDependency, error) {
	ret := _m.Called(tx, _a1, version)

	if len(ret) == 0 {
		panic("no return value specified for LoadAssetComponents")
	}

	var r0 []models.ComponentDependency
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, models.Asset, string) ([]models.ComponentDependency, error)); ok {
		return rf(tx, _a1, version)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, models.Asset, string) []models.ComponentDependency); ok {
		r0 = rf(tx, _a1, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ComponentDependency)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, models.Asset, string) error); ok {
		r1 = rf(tx, _a1, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetComponentRepository_LoadAssetComponents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoadAssetComponents'
type AssetComponentRepository_LoadAssetComponents_Call struct {
	*mock.Call
}

// LoadAssetComponents is a helper method to define mock.On call
//   - tx *gorm.DB
//   - _a1 models.Asset
//   - version string
func (_e *AssetComponentRepository_Expecter) LoadAssetComponents(tx interface{}, _a1 interface{}, version interface{}) *AssetComponentRepository_LoadAssetComponents_Call {
	return &AssetComponentRepository_LoadAssetComponents_Call{Call: _e.mock.On("LoadAssetComponents", tx, _a1, version)}
}

func (_c *AssetComponentRepository_LoadAssetComponents_Call) Run(run func(tx *gorm.DB, _a1 models.Asset, version string)) *AssetComponentRepository_LoadAssetComponents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(models.Asset), args[2].(string))
	})
	return _c
}

func (_c *AssetComponentRepository_LoadAssetComponents_Call) Return(_a0 []models.ComponentDependency, _a1 error) *AssetComponentRepository_LoadAssetComponents_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetComponentRepository_LoadAssetComponents_Call) RunAndReturn(run func(*gorm.DB, models.Asset, string) ([]models.ComponentDependency, error)) *AssetComponentRepository_LoadAssetComponents_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, components
func (_m *AssetComponentRepository) SaveBatch(tx *gorm.DB, components []models.Component) error {
	ret := _m.Called(tx, components)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Component) error); ok {
		r0 = rf(tx, components)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetComponentRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type AssetComponentRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - components []models.Component
func (_e *AssetComponentRepository_Expecter) SaveBatch(tx interface{}, components interface{}) *AssetComponentRepository_SaveBatch_Call {
	return &AssetComponentRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, components)}
}

func (_c *AssetComponentRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, components []models.Component)) *AssetComponentRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Component))
	})
	return _c
}

func (_c *AssetComponentRepository_SaveBatch_Call) Return(_a0 error) *AssetComponentRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetComponentRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Component) error) *AssetComponentRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetComponentRepository creates a new instance of AssetComponentRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetComponentRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetComponentRepository {
	mock := &AssetComponentRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}