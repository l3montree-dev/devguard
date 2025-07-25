// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// NewAssetRiskHistoryRepository creates a new instance of AssetRiskHistoryRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetRiskHistoryRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetRiskHistoryRepository {
	mock := &AssetRiskHistoryRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// AssetRiskHistoryRepository is an autogenerated mock type for the AssetRiskHistoryRepository type
type AssetRiskHistoryRepository struct {
	mock.Mock
}

type AssetRiskHistoryRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetRiskHistoryRepository) EXPECT() *AssetRiskHistoryRepository_Expecter {
	return &AssetRiskHistoryRepository_Expecter{mock: &_m.Mock}
}

// GetRiskHistory provides a mock function for the type AssetRiskHistoryRepository
func (_mock *AssetRiskHistoryRepository) GetRiskHistory(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	ret := _mock.Called(assetVersionName, assetID, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistory")
	}

	var r0 []models.AssetRiskHistory
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, time.Time, time.Time) ([]models.AssetRiskHistory, error)); ok {
		return returnFunc(assetVersionName, assetID, start, end)
	}
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, time.Time, time.Time) []models.AssetRiskHistory); ok {
		r0 = returnFunc(assetVersionName, assetID, start, end)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetRiskHistory)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, uuid.UUID, time.Time, time.Time) error); ok {
		r1 = returnFunc(assetVersionName, assetID, start, end)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// AssetRiskHistoryRepository_GetRiskHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRiskHistory'
type AssetRiskHistoryRepository_GetRiskHistory_Call struct {
	*mock.Call
}

// GetRiskHistory is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *AssetRiskHistoryRepository_Expecter) GetRiskHistory(assetVersionName interface{}, assetID interface{}, start interface{}, end interface{}) *AssetRiskHistoryRepository_GetRiskHistory_Call {
	return &AssetRiskHistoryRepository_GetRiskHistory_Call{Call: _e.mock.On("GetRiskHistory", assetVersionName, assetID, start, end)}
}

func (_c *AssetRiskHistoryRepository_GetRiskHistory_Call) Run(run func(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time)) *AssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		var arg2 time.Time
		if args[2] != nil {
			arg2 = args[2].(time.Time)
		}
		var arg3 time.Time
		if args[3] != nil {
			arg3 = args[3].(time.Time)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
		)
	})
	return _c
}

func (_c *AssetRiskHistoryRepository_GetRiskHistory_Call) Return(assetRiskHistorys []models.AssetRiskHistory, err error) *AssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(assetRiskHistorys, err)
	return _c
}

func (_c *AssetRiskHistoryRepository_GetRiskHistory_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error)) *AssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// GetRiskHistoryByProject provides a mock function for the type AssetRiskHistoryRepository
func (_mock *AssetRiskHistoryRepository) GetRiskHistoryByProject(projectID uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error) {
	ret := _mock.Called(projectID, day)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistoryByProject")
	}

	var r0 []models.AssetRiskHistory
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, time.Time) ([]models.AssetRiskHistory, error)); ok {
		return returnFunc(projectID, day)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, time.Time) []models.AssetRiskHistory); ok {
		r0 = returnFunc(projectID, day)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetRiskHistory)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID, time.Time) error); ok {
		r1 = returnFunc(projectID, day)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// AssetRiskHistoryRepository_GetRiskHistoryByProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRiskHistoryByProject'
type AssetRiskHistoryRepository_GetRiskHistoryByProject_Call struct {
	*mock.Call
}

// GetRiskHistoryByProject is a helper method to define mock.On call
//   - projectID uuid.UUID
//   - day time.Time
func (_e *AssetRiskHistoryRepository_Expecter) GetRiskHistoryByProject(projectID interface{}, day interface{}) *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	return &AssetRiskHistoryRepository_GetRiskHistoryByProject_Call{Call: _e.mock.On("GetRiskHistoryByProject", projectID, day)}
}

func (_c *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call) Run(run func(projectID uuid.UUID, day time.Time)) *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 uuid.UUID
		if args[0] != nil {
			arg0 = args[0].(uuid.UUID)
		}
		var arg1 time.Time
		if args[1] != nil {
			arg1 = args[1].(time.Time)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call) Return(assetRiskHistorys []models.AssetRiskHistory, err error) *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Return(assetRiskHistorys, err)
	return _c
}

func (_c *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call) RunAndReturn(run func(projectID uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error)) *AssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRiskAggregation provides a mock function for the type AssetRiskHistoryRepository
func (_mock *AssetRiskHistoryRepository) UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error {
	ret := _mock.Called(assetRisk)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRiskAggregation")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(*models.AssetRiskHistory) error); ok {
		r0 = returnFunc(assetRisk)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// AssetRiskHistoryRepository_UpdateRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateRiskAggregation'
type AssetRiskHistoryRepository_UpdateRiskAggregation_Call struct {
	*mock.Call
}

// UpdateRiskAggregation is a helper method to define mock.On call
//   - assetRisk *models.AssetRiskHistory
func (_e *AssetRiskHistoryRepository_Expecter) UpdateRiskAggregation(assetRisk interface{}) *AssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	return &AssetRiskHistoryRepository_UpdateRiskAggregation_Call{Call: _e.mock.On("UpdateRiskAggregation", assetRisk)}
}

func (_c *AssetRiskHistoryRepository_UpdateRiskAggregation_Call) Run(run func(assetRisk *models.AssetRiskHistory)) *AssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 *models.AssetRiskHistory
		if args[0] != nil {
			arg0 = args[0].(*models.AssetRiskHistory)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *AssetRiskHistoryRepository_UpdateRiskAggregation_Call) Return(err error) *AssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *AssetRiskHistoryRepository_UpdateRiskAggregation_Call) RunAndReturn(run func(assetRisk *models.AssetRiskHistory) error) *AssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}
