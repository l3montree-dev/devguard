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

// NewStatisticsRepository creates a new instance of StatisticsRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsRepository {
	mock := &StatisticsRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// StatisticsRepository is an autogenerated mock type for the StatisticsRepository type
type StatisticsRepository struct {
	mock.Mock
}

type StatisticsRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsRepository) EXPECT() *StatisticsRepository_Expecter {
	return &StatisticsRepository_Expecter{mock: &_m.Mock}
}

// AverageFixingTime provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) AverageFixingTime(assetVersionName string, assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64) (time.Duration, error) {
	ret := _mock.Called(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)

	if len(ret) == 0 {
		panic("no return value specified for AverageFixingTime")
	}

	var r0 time.Duration
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, float64, float64) (time.Duration, error)); ok {
		return returnFunc(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	}
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, float64, float64) time.Duration); ok {
		r0 = returnFunc(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r0 = ret.Get(0).(time.Duration)
	}
	if returnFunc, ok := ret.Get(1).(func(string, uuid.UUID, float64, float64) error); ok {
		r1 = returnFunc(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// StatisticsRepository_AverageFixingTime_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AverageFixingTime'
type StatisticsRepository_AverageFixingTime_Call struct {
	*mock.Call
}

// AverageFixingTime is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - riskIntervalStart float64
//   - riskIntervalEnd float64
func (_e *StatisticsRepository_Expecter) AverageFixingTime(assetVersionName interface{}, assetID interface{}, riskIntervalStart interface{}, riskIntervalEnd interface{}) *StatisticsRepository_AverageFixingTime_Call {
	return &StatisticsRepository_AverageFixingTime_Call{Call: _e.mock.On("AverageFixingTime", assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)}
}

func (_c *StatisticsRepository_AverageFixingTime_Call) Run(run func(assetVersionName string, assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64)) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		var arg2 float64
		if args[2] != nil {
			arg2 = args[2].(float64)
		}
		var arg3 float64
		if args[3] != nil {
			arg3 = args[3].(float64)
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

func (_c *StatisticsRepository_AverageFixingTime_Call) Return(duration time.Duration, err error) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(duration, err)
	return _c
}

func (_c *StatisticsRepository_AverageFixingTime_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64) (time.Duration, error)) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(run)
	return _c
}

// CVESWithKnownExploitsInAssetVersion provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) CVESWithKnownExploitsInAssetVersion(assetVersion models.AssetVersion) ([]models.CVE, error) {
	ret := _mock.Called(assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for CVESWithKnownExploitsInAssetVersion")
	}

	var r0 []models.CVE
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(models.AssetVersion) ([]models.CVE, error)); ok {
		return returnFunc(assetVersion)
	}
	if returnFunc, ok := ret.Get(0).(func(models.AssetVersion) []models.CVE); ok {
		r0 = returnFunc(assetVersion)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.CVE)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(models.AssetVersion) error); ok {
		r1 = returnFunc(assetVersion)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CVESWithKnownExploitsInAssetVersion'
type StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call struct {
	*mock.Call
}

// CVESWithKnownExploitsInAssetVersion is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
func (_e *StatisticsRepository_Expecter) CVESWithKnownExploitsInAssetVersion(assetVersion interface{}) *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call {
	return &StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call{Call: _e.mock.On("CVESWithKnownExploitsInAssetVersion", assetVersion)}
}

func (_c *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call) Run(run func(assetVersion models.AssetVersion)) *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.AssetVersion
		if args[0] != nil {
			arg0 = args[0].(models.AssetVersion)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call) Return(cVEs []models.CVE, err error) *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call {
	_c.Call.Return(cVEs, err)
	return _c
}

func (_c *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call) RunAndReturn(run func(assetVersion models.AssetVersion) ([]models.CVE, error)) *StatisticsRepository_CVESWithKnownExploitsInAssetVersion_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetCvssDistribution provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) GetAssetCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _mock.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetCvssDistribution")
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

// StatisticsRepository_GetAssetCvssDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetCvssDistribution'
type StatisticsRepository_GetAssetCvssDistribution_Call struct {
	*mock.Call
}

// GetAssetCvssDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsRepository_Expecter) GetAssetCvssDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsRepository_GetAssetCvssDistribution_Call {
	return &StatisticsRepository_GetAssetCvssDistribution_Call{Call: _e.mock.On("GetAssetCvssDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsRepository_GetAssetCvssDistribution_Call {
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

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) Return(assetRiskDistribution models.AssetRiskDistribution, err error) *StatisticsRepository_GetAssetCvssDistribution_Call {
	_c.Call.Return(assetRiskDistribution, err)
	return _c
}

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)) *StatisticsRepository_GetAssetCvssDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetRiskDistribution provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) GetAssetRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _mock.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetRiskDistribution")
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

// StatisticsRepository_GetAssetRiskDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetRiskDistribution'
type StatisticsRepository_GetAssetRiskDistribution_Call struct {
	*mock.Call
}

// GetAssetRiskDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsRepository_Expecter) GetAssetRiskDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsRepository_GetAssetRiskDistribution_Call {
	return &StatisticsRepository_GetAssetRiskDistribution_Call{Call: _e.mock.On("GetAssetRiskDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsRepository_GetAssetRiskDistribution_Call {
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

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) Return(assetRiskDistribution models.AssetRiskDistribution, err error) *StatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(assetRiskDistribution, err)
	return _c
}

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error)) *StatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnCountByScannerID provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) GetDependencyVulnCountByScannerID(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	ret := _mock.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnCountByScannerID")
	}

	var r0 map[string]int
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID) (map[string]int, error)); ok {
		return returnFunc(assetVersionName, assetID)
	}
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID) map[string]int); ok {
		r0 = returnFunc(assetVersionName, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]int)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, uuid.UUID) error); ok {
		r1 = returnFunc(assetVersionName, assetID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// StatisticsRepository_GetDependencyVulnCountByScannerID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnCountByScannerID'
type StatisticsRepository_GetDependencyVulnCountByScannerID_Call struct {
	*mock.Call
}

// GetDependencyVulnCountByScannerID is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *StatisticsRepository_Expecter) GetDependencyVulnCountByScannerID(assetVersionName interface{}, assetID interface{}) *StatisticsRepository_GetDependencyVulnCountByScannerID_Call {
	return &StatisticsRepository_GetDependencyVulnCountByScannerID_Call{Call: _e.mock.On("GetDependencyVulnCountByScannerID", assetVersionName, assetID)}
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerID_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *StatisticsRepository_GetDependencyVulnCountByScannerID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerID_Call) Return(stringToInt map[string]int, err error) *StatisticsRepository_GetDependencyVulnCountByScannerID_Call {
	_c.Call.Return(stringToInt, err)
	return _c
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerID_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID) (map[string]int, error)) *StatisticsRepository_GetDependencyVulnCountByScannerID_Call {
	_c.Call.Return(run)
	return _c
}

// TimeTravelDependencyVulnState provides a mock function for the type StatisticsRepository
func (_mock *StatisticsRepository) TimeTravelDependencyVulnState(assetVersionName string, assetID uuid.UUID, time1 time.Time) ([]models.DependencyVuln, error) {
	ret := _mock.Called(assetVersionName, assetID, time1)

	if len(ret) == 0 {
		panic("no return value specified for TimeTravelDependencyVulnState")
	}

	var r0 []models.DependencyVuln
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) ([]models.DependencyVuln, error)); ok {
		return returnFunc(assetVersionName, assetID, time1)
	}
	if returnFunc, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) []models.DependencyVuln); ok {
		r0 = returnFunc(assetVersionName, assetID, time1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string, uuid.UUID, time.Time) error); ok {
		r1 = returnFunc(assetVersionName, assetID, time1)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// StatisticsRepository_TimeTravelDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TimeTravelDependencyVulnState'
type StatisticsRepository_TimeTravelDependencyVulnState_Call struct {
	*mock.Call
}

// TimeTravelDependencyVulnState is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - time1 time.Time
func (_e *StatisticsRepository_Expecter) TimeTravelDependencyVulnState(assetVersionName interface{}, assetID interface{}, time1 interface{}) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	return &StatisticsRepository_TimeTravelDependencyVulnState_Call{Call: _e.mock.On("TimeTravelDependencyVulnState", assetVersionName, assetID, time1)}
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) Run(run func(assetVersionName string, assetID uuid.UUID, time1 time.Time)) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
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
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) Return(dependencyVulns []models.DependencyVuln, err error) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(dependencyVulns, err)
	return _c
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) RunAndReturn(run func(assetVersionName string, assetID uuid.UUID, time1 time.Time) ([]models.DependencyVuln, error)) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}
