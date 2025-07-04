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

// NewStatisticsService creates a new instance of StatisticsService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsService(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsService {
	mock := &StatisticsService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// StatisticsService is an autogenerated mock type for the StatisticsService type
type StatisticsService struct {
	mock.Mock
}

type StatisticsService_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsService) EXPECT() *StatisticsService_Expecter {
	return &StatisticsService_Expecter{mock: &_m.Mock}
}

// GetAssetVersionCvssDistribution provides a mock function for the type StatisticsService
func (_mock *StatisticsService) GetAssetVersionCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _mock.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetVersionCvssDistribution")
	}

	var r0 models.AssetRiskDistribution
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)); ok {
		return returnFunc(assetVersionName, assetID, assetName)
	}
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, string) models.AssetRiskDistribution); ok {
		r0 = returnFunc(assetVersionName, assetID, assetName)
	} else {
		r0 = ret.Get(0).(models.AssetRiskDistribution)
	}
	if returnFunc, ok := ret.Get(1).(func(string, uuid.UUID, string) error); ok {
		r1 = returnFunc(assetVersionName, assetID, assetName)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// StatisticsService_GetAssetVersionCvssDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionCvssDistribution'
type StatisticsService_GetAssetVersionCvssDistribution_Call struct {
	*mock.Call
}

// GetAssetVersionCvssDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsService_Expecter) GetAssetVersionCvssDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsService_GetAssetVersionCvssDistribution_Call {
	return &StatisticsService_GetAssetVersionCvssDistribution_Call{Call: _e.mock.On("GetAssetVersionCvssDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsService_GetAssetVersionCvssDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsService_GetAssetVersionCvssDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *StatisticsService_GetAssetVersionCvssDistribution_Call) Return(assetRiskDistribution models.AssetRiskDistribution, err error) *StatisticsService_GetAssetVersionCvssDistribution_Call {
	_c.Call.Return(assetRiskDistribution, err)
	return _c
}

func (_c *StatisticsService_GetAssetVersionCvssDistribution_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)) *StatisticsService_GetAssetVersionCvssDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateAssetRiskAggregation provides a mock function for the type StatisticsService
func (_mock *StatisticsService) UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool) error {
	ret := _mock.Called(assetVersion, assetID, begin, end, propagateToProject)

	if len(ret) == 0 {
		panic("no return value specified for UpdateAssetRiskAggregation")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(*models.AssetVersion, uuid.UUID, time.Time, time.Time, bool) error); ok {
		r0 = returnFunc(assetVersion, assetID, begin, end, propagateToProject)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// StatisticsService_UpdateAssetRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateAssetRiskAggregation'
type StatisticsService_UpdateAssetRiskAggregation_Call struct {
	*mock.Call
}

// UpdateAssetRiskAggregation is a helper method to define mock.On call
//   - assetVersion *models.AssetVersion
//   - assetID uuid.UUID
//   - begin time.Time
//   - end time.Time
//   - propagateToProject bool
func (_e *StatisticsService_Expecter) UpdateAssetRiskAggregation(assetVersion interface{}, assetID interface{}, begin interface{}, end interface{}, propagateToProject interface{}) *StatisticsService_UpdateAssetRiskAggregation_Call {
	return &StatisticsService_UpdateAssetRiskAggregation_Call{Call: _e.mock.On("UpdateAssetRiskAggregation", assetVersion, assetID, begin, end, propagateToProject)}
}

func (_c *StatisticsService_UpdateAssetRiskAggregation_Call) Run(run func(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool)) *StatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 *models.AssetVersion
		if args[0] != nil {
			arg0 = args[0].(*models.AssetVersion)
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
		var arg4 bool
		if args[4] != nil {
			arg4 = args[4].(bool)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
			arg4,
		)
	})
	return _c
}

func (_c *StatisticsService_UpdateAssetRiskAggregation_Call) Return(err error) *StatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *StatisticsService_UpdateAssetRiskAggregation_Call) RunAndReturn(run func(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool) error) *StatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}
