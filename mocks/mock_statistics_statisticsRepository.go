// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	time "time"

	uuid "github.com/google/uuid"
)

// StatisticsStatisticsRepository is an autogenerated mock type for the statisticsRepository type
type StatisticsStatisticsRepository struct {
	mock.Mock
}

type StatisticsStatisticsRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsStatisticsRepository) EXPECT() *StatisticsStatisticsRepository_Expecter {
	return &StatisticsStatisticsRepository_Expecter{mock: &_m.Mock}
}

// AverageFixingTime provides a mock function with given fields: assetID, riskIntervalStart, riskIntervalEnd
func (_m *StatisticsStatisticsRepository) AverageFixingTime(assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64) (time.Duration, error) {
	ret := _m.Called(assetID, riskIntervalStart, riskIntervalEnd)

	if len(ret) == 0 {
		panic("no return value specified for AverageFixingTime")
	}

	var r0 time.Duration
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, float64, float64) (time.Duration, error)); ok {
		return rf(assetID, riskIntervalStart, riskIntervalEnd)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, float64, float64) time.Duration); ok {
		r0 = rf(assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, float64, float64) error); ok {
		r1 = rf(assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_AverageFixingTime_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AverageFixingTime'
type StatisticsStatisticsRepository_AverageFixingTime_Call struct {
	*mock.Call
}

// AverageFixingTime is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - riskIntervalStart float64
//   - riskIntervalEnd float64
func (_e *StatisticsStatisticsRepository_Expecter) AverageFixingTime(assetID interface{}, riskIntervalStart interface{}, riskIntervalEnd interface{}) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	return &StatisticsStatisticsRepository_AverageFixingTime_Call{Call: _e.mock.On("AverageFixingTime", assetID, riskIntervalStart, riskIntervalEnd)}
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) Run(run func(assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64)) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(float64), args[2].(float64))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) Return(_a0 time.Duration, _a1 error) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) RunAndReturn(run func(uuid.UUID, float64, float64) (time.Duration, error)) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetRiskDistribution provides a mock function with given fields: assetID, assetName
func (_m *StatisticsStatisticsRepository) GetAssetRiskDistribution(assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _m.Called(assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetRiskDistribution")
	}

	var r0 models.AssetRiskDistribution
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) (models.AssetRiskDistribution, error)); ok {
		return rf(assetID, assetName)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) models.AssetRiskDistribution); ok {
		r0 = rf(assetID, assetName)
	} else {
		r0 = ret.Get(0).(models.AssetRiskDistribution)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = rf(assetID, assetName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_GetAssetRiskDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetRiskDistribution'
type StatisticsStatisticsRepository_GetAssetRiskDistribution_Call struct {
	*mock.Call
}

// GetAssetRiskDistribution is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsStatisticsRepository_Expecter) GetAssetRiskDistribution(assetID interface{}, assetName interface{}) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	return &StatisticsStatisticsRepository_GetAssetRiskDistribution_Call{Call: _e.mock.On("GetAssetRiskDistribution", assetID, assetName)}
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) Run(run func(assetID uuid.UUID, assetName string)) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) Return(_a0 models.AssetRiskDistribution, _a1 error) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) RunAndReturn(run func(uuid.UUID, string) (models.AssetRiskDistribution, error)) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnCountByScannerId provides a mock function with given fields: assetID
func (_m *StatisticsStatisticsRepository) GetDependencyVulnCountByScannerId(assetID uuid.UUID) (map[string]int, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnCountByScannerId")
	}

	var r0 map[string]int
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (map[string]int, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) map[string]int); ok {
		r0 = rf(assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]int)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnCountByScannerId'
type StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call struct {
	*mock.Call
}

// GetDependencyVulnCountByScannerId is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *StatisticsStatisticsRepository_Expecter) GetDependencyVulnCountByScannerId(assetID interface{}) *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	return &StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call{Call: _e.mock.On("GetDependencyVulnCountByScannerId", assetID)}
}

func (_c *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call) Run(run func(assetID uuid.UUID)) *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call) Return(_a0 map[string]int, _a1 error) *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call) RunAndReturn(run func(uuid.UUID) (map[string]int, error)) *StatisticsStatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(run)
	return _c
}

// TimeTravelDependencyVulnState provides a mock function with given fields: assetID, _a1
func (_m *StatisticsStatisticsRepository) TimeTravelDependencyVulnState(assetID uuid.UUID, _a1 time.Time) ([]models.DependencyVuln, error) {
	ret := _m.Called(assetID, _a1)

	if len(ret) == 0 {
		panic("no return value specified for TimeTravelDependencyVulnState")
	}

	var r0 []models.DependencyVuln
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) ([]models.DependencyVuln, error)); ok {
		return rf(assetID, _a1)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) []models.DependencyVuln); ok {
		r0 = rf(assetID, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, time.Time) error); ok {
		r1 = rf(assetID, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TimeTravelDependencyVulnState'
type StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call struct {
	*mock.Call
}

// TimeTravelDependencyVulnState is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - _a1 time.Time
func (_e *StatisticsStatisticsRepository_Expecter) TimeTravelDependencyVulnState(assetID interface{}, _a1 interface{}) *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call {
	return &StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call{Call: _e.mock.On("TimeTravelDependencyVulnState", assetID, _a1)}
}

func (_c *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call) Run(run func(assetID uuid.UUID, _a1 time.Time)) *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call) Return(_a0 []models.DependencyVuln, _a1 error) *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call) RunAndReturn(run func(uuid.UUID, time.Time) ([]models.DependencyVuln, error)) *StatisticsStatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsStatisticsRepository creates a new instance of StatisticsStatisticsRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsStatisticsRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsStatisticsRepository {
	mock := &StatisticsStatisticsRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
