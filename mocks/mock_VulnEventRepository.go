// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

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

// ReadAssetEventsByVulnID provides a mock function for the type VulnEventRepository
func (_mock *VulnEventRepository) ReadAssetEventsByVulnID(vulnID string, vulnType models.VulnType) ([]models.VulnEventDetail, error) {
	ret := _mock.Called(vulnID, vulnType)

	if len(ret) == 0 {
		panic("no return value specified for ReadAssetEventsByVulnID")
	}

	var r0 []models.VulnEventDetail
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, models.VulnType) ([]models.VulnEventDetail, error)); ok {
		return returnFunc(vulnID, vulnType)
	}
	if returnFunc, ok := ret.Get(0).(func(string, models.VulnType) []models.VulnEventDetail); ok {
		r0 = returnFunc(vulnID, vulnType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.VulnEventDetail)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, models.VulnType) error); ok {
		r1 = returnFunc(vulnID, vulnType)
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
//   - vulnID
//   - vulnType
func (_e *VulnEventRepository_Expecter) ReadAssetEventsByVulnID(vulnID interface{}, vulnType interface{}) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	return &VulnEventRepository_ReadAssetEventsByVulnID_Call{Call: _e.mock.On("ReadAssetEventsByVulnID", vulnID, vulnType)}
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) Run(run func(vulnID string, vulnType models.VulnType)) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(models.VulnType))
	})
	return _c
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) Return(vulnEventDetails []models.VulnEventDetail, err error) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Return(vulnEventDetails, err)
	return _c
}

func (_c *VulnEventRepository_ReadAssetEventsByVulnID_Call) RunAndReturn(run func(vulnID string, vulnType models.VulnType) ([]models.VulnEventDetail, error)) *VulnEventRepository_ReadAssetEventsByVulnID_Call {
	_c.Call.Return(run)
	return _c
}

// ReadEventsByAssetIDAndAssetVersionName provides a mock function for the type VulnEventRepository
func (_mock *VulnEventRepository) ReadEventsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string, pageInfo core.PageInfo, filter []core.FilterQuery) (core.Paged[models.VulnEventDetail], error) {
	ret := _mock.Called(assetID, assetVersionName, pageInfo, filter)

	if len(ret) == 0 {
		panic("no return value specified for ReadEventsByAssetIDAndAssetVersionName")
	}

	var r0 core.Paged[models.VulnEventDetail]
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string, core.PageInfo, []core.FilterQuery) (core.Paged[models.VulnEventDetail], error)); ok {
		return returnFunc(assetID, assetVersionName, pageInfo, filter)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string, core.PageInfo, []core.FilterQuery) core.Paged[models.VulnEventDetail]); ok {
		r0 = returnFunc(assetID, assetVersionName, pageInfo, filter)
	} else {
		r0 = ret.Get(0).(core.Paged[models.VulnEventDetail])
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID, string, core.PageInfo, []core.FilterQuery) error); ok {
		r1 = returnFunc(assetID, assetVersionName, pageInfo, filter)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadEventsByAssetIDAndAssetVersionName'
type VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call struct {
	*mock.Call
}

// ReadEventsByAssetIDAndAssetVersionName is a helper method to define mock.On call
//   - assetID
//   - assetVersionName
//   - pageInfo
//   - filter
func (_e *VulnEventRepository_Expecter) ReadEventsByAssetIDAndAssetVersionName(assetID interface{}, assetVersionName interface{}, pageInfo interface{}, filter interface{}) *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call {
	return &VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call{Call: _e.mock.On("ReadEventsByAssetIDAndAssetVersionName", assetID, assetVersionName, pageInfo, filter)}
}

func (_c *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call) Run(run func(assetID uuid.UUID, assetVersionName string, pageInfo core.PageInfo, filter []core.FilterQuery)) *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string), args[2].(core.PageInfo), args[3].([]core.FilterQuery))
	})
	return _c
}

func (_c *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call) Return(paged core.Paged[models.VulnEventDetail], err error) *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call {
	_c.Call.Return(paged, err)
	return _c
}

func (_c *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call) RunAndReturn(run func(assetID uuid.UUID, assetVersionName string, pageInfo core.PageInfo, filter []core.FilterQuery) (core.Paged[models.VulnEventDetail], error)) *VulnEventRepository_ReadEventsByAssetIDAndAssetVersionName_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function for the type VulnEventRepository
func (_mock *VulnEventRepository) Save(db core.DB, event *models.VulnEvent) error {
	ret := _mock.Called(db, event)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, *models.VulnEvent) error); ok {
		r0 = returnFunc(db, event)
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
//   - db
//   - event
func (_e *VulnEventRepository_Expecter) Save(db interface{}, event interface{}) *VulnEventRepository_Save_Call {
	return &VulnEventRepository_Save_Call{Call: _e.mock.On("Save", db, event)}
}

func (_c *VulnEventRepository_Save_Call) Run(run func(db core.DB, event *models.VulnEvent)) *VulnEventRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].(*models.VulnEvent))
	})
	return _c
}

func (_c *VulnEventRepository_Save_Call) Return(err error) *VulnEventRepository_Save_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *VulnEventRepository_Save_Call) RunAndReturn(run func(db core.DB, event *models.VulnEvent) error) *VulnEventRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function for the type VulnEventRepository
func (_mock *VulnEventRepository) SaveBatch(db core.DB, events []models.VulnEvent) error {
	ret := _mock.Called(db, events)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, []models.VulnEvent) error); ok {
		r0 = returnFunc(db, events)
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
//   - db
//   - events
func (_e *VulnEventRepository_Expecter) SaveBatch(db interface{}, events interface{}) *VulnEventRepository_SaveBatch_Call {
	return &VulnEventRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", db, events)}
}

func (_c *VulnEventRepository_SaveBatch_Call) Run(run func(db core.DB, events []models.VulnEvent)) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].([]models.VulnEvent))
	})
	return _c
}

func (_c *VulnEventRepository_SaveBatch_Call) Return(err error) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *VulnEventRepository_SaveBatch_Call) RunAndReturn(run func(db core.DB, events []models.VulnEvent) error) *VulnEventRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}
