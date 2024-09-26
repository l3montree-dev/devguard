// Code generated by mockery v2.42.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// StatisticsAssetRepository is an autogenerated mock type for the assetRepository type
type StatisticsAssetRepository struct {
	mock.Mock
}

type StatisticsAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsAssetRepository) EXPECT() *StatisticsAssetRepository_Expecter {
	return &StatisticsAssetRepository_Expecter{mock: &_m.Mock}
}

// GetAllAssetsFromDB provides a mock function with given fields:
func (_m *StatisticsAssetRepository) GetAllAssetsFromDB() ([]models.Asset, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetAllAssetsFromDB")
	}

	var r0 []models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.Asset, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.Asset); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Asset)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsAssetRepository_GetAllAssetsFromDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllAssetsFromDB'
type StatisticsAssetRepository_GetAllAssetsFromDB_Call struct {
	*mock.Call
}

// GetAllAssetsFromDB is a helper method to define mock.On call
func (_e *StatisticsAssetRepository_Expecter) GetAllAssetsFromDB() *StatisticsAssetRepository_GetAllAssetsFromDB_Call {
	return &StatisticsAssetRepository_GetAllAssetsFromDB_Call{Call: _e.mock.On("GetAllAssetsFromDB")}
}

func (_c *StatisticsAssetRepository_GetAllAssetsFromDB_Call) Run(run func()) *StatisticsAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *StatisticsAssetRepository_GetAllAssetsFromDB_Call) Return(_a0 []models.Asset, _a1 error) *StatisticsAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsAssetRepository_GetAllAssetsFromDB_Call) RunAndReturn(run func() ([]models.Asset, error)) *StatisticsAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Return(run)
	return _c
}

// GetByProjectID provides a mock function with given fields: projectID
func (_m *StatisticsAssetRepository) GetByProjectID(projectID uuid.UUID) ([]models.Asset, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetByProjectID")
	}

	var r0 []models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Asset, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Asset); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Asset)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsAssetRepository_GetByProjectID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByProjectID'
type StatisticsAssetRepository_GetByProjectID_Call struct {
	*mock.Call
}

// GetByProjectID is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *StatisticsAssetRepository_Expecter) GetByProjectID(projectID interface{}) *StatisticsAssetRepository_GetByProjectID_Call {
	return &StatisticsAssetRepository_GetByProjectID_Call{Call: _e.mock.On("GetByProjectID", projectID)}
}

func (_c *StatisticsAssetRepository_GetByProjectID_Call) Run(run func(projectID uuid.UUID)) *StatisticsAssetRepository_GetByProjectID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsAssetRepository_GetByProjectID_Call) Return(_a0 []models.Asset, _a1 error) *StatisticsAssetRepository_GetByProjectID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsAssetRepository_GetByProjectID_Call) RunAndReturn(run func(uuid.UUID) ([]models.Asset, error)) *StatisticsAssetRepository_GetByProjectID_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, asset
func (_m *StatisticsAssetRepository) Save(tx *gorm.DB, asset *models.Asset) error {
	ret := _m.Called(tx, asset)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Asset) error); ok {
		r0 = rf(tx, asset)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StatisticsAssetRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type StatisticsAssetRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - asset *models.Asset
func (_e *StatisticsAssetRepository_Expecter) Save(tx interface{}, asset interface{}) *StatisticsAssetRepository_Save_Call {
	return &StatisticsAssetRepository_Save_Call{Call: _e.mock.On("Save", tx, asset)}
}

func (_c *StatisticsAssetRepository_Save_Call) Run(run func(tx *gorm.DB, asset *models.Asset)) *StatisticsAssetRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Asset))
	})
	return _c
}

func (_c *StatisticsAssetRepository_Save_Call) Return(_a0 error) *StatisticsAssetRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *StatisticsAssetRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Asset) error) *StatisticsAssetRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsAssetRepository creates a new instance of StatisticsAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsAssetRepository {
	mock := &StatisticsAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}