// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// VulnEventRepository is an autogenerated mock type for the VulnEventRepository type
type VulnEventRepository struct {
	mock.Mock
}

type VulnEventRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *VulnEventRepository) EXPECT() *VulnEventRepository_Expecter {
	return &VulnEventRepository_Expecter{mock: &_m.Mock}
}

// ReadAssetEventsByVulnID provides a mock function with given fields: vulnID
func (_m *VulnEventRepository) ReadAssetEventsByVulnID(vulnID string) ([]models.VulnEventDetail, error) {
	ret := _m.Called(vulnID)

	if len(ret) == 0 {
		panic("no return value specified for ReadAssetEventsByVulnID")
	}

	var r0 []models.VulnEventDetail
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]models.VulnEventDetail, error)); ok {
		return rf(vulnID)
	}
	if rf, ok := ret.Get(0).(func(string) []models.VulnEventDetail); ok {
		r0 = rf(vulnID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.VulnEventDetail)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(vulnID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VulnEventRepository_ReadAssetEventsByVulnID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadAssetEventsByVulnID'
type VulnEventRepository_ReadAssetEventsByVulnID_Call struct {
	*mock.Call
}

// ReadAssetEventsByVulnID is a helper method to define mock.On call
//   - vulnID string
func (_e *VulnEventRepository_Expecter) ReadAssetEventsByVulnID(vulnID interface{}) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	return &VulnEventRepository_ReadAssetEventsByVulnID_Call{Call: _e.mock.On("ReadAssetEventsByVulnID", vulnID)}
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) Run(run func(vulnID string)) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) Return(_a0 []models.VulnEventDetail, _a1 error) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) RunAndReturn(run func(string) ([]models.VulnEventDetail, error)) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: db, event
func (_m *VulnEventRepository) Save(db *gorm.DB, event *models.VulnEvent) error {
	ret := _m.Called(db, event)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.VulnEvent) error); ok {
		r0 = rf(db, event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VulnEventRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type VulnEventRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - event *models.VulnEvent
func (_e *VulnEventRepository_Expecter) Save(db interface{}, event interface{}) *VulnEventRepository_Save_Call {
	return &VulnEventRepository_Save_Call{Call: _e.mock.On("Save", db, event)}
}

func (_c *VulnEventRepository_Save_Call) Run(run func(db *gorm.DB, event *models.VulnEvent)) *VulnEventRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.VulnEvent))
	})
	return _c
}

func (_c *VulnEventRepository_Save_Call) Return(_a0 error) *VulnEventRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *VulnEventRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.VulnEvent) error) *VulnEventRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: db, events
func (_m *VulnEventRepository) SaveBatch(db *gorm.DB, events []models.VulnEvent) error {
	ret := _m.Called(db, events)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.VulnEvent) error); ok {
		r0 = rf(db, events)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VulnEventRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type VulnEventRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - db *gorm.DB
//   - events []models.VulnEvent
func (_e *VulnEventRepository_Expecter) SaveBatch(db interface{}, events interface{}) *VulnEventRepository_SaveBatch_Call {
	return &VulnEventRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", db, events)}
}

func (_c *VulnEventRepository_SaveBatch_Call) Run(run func(db *gorm.DB, events []models.VulnEvent)) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.VulnEvent))
	})
	return _c
}

func (_c *VulnEventRepository_SaveBatch_Call) Return(_a0 error) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *VulnEventRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.VulnEvent) error) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewVulnEventRepository creates a new instance of VulnEventRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewVulnEventRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *VulnEventRepository {
	mock := &VulnEventRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
