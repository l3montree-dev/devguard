// Code generated by mockery v2.42.2. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	time "time"

	uuid "github.com/google/uuid"
)

// ScanStatisticsService is an autogenerated mock type for the statisticsService type
type ScanStatisticsService struct {
	mock.Mock
}

type ScanStatisticsService_Expecter struct {
	mock *mock.Mock
}

func (_m *ScanStatisticsService) EXPECT() *ScanStatisticsService_Expecter {
	return &ScanStatisticsService_Expecter{mock: &_m.Mock}
}

// UpdateAssetRiskAggregation provides a mock function with given fields: assetID, begin, end, updateProject
func (_m *ScanStatisticsService) UpdateAssetRiskAggregation(assetID uuid.UUID, begin time.Time, end time.Time, updateProject bool) error {
	ret := _m.Called(assetID, begin, end, updateProject)

	if len(ret) == 0 {
		panic("no return value specified for UpdateAssetRiskAggregation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time, bool) error); ok {
		r0 = rf(assetID, begin, end, updateProject)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ScanStatisticsService_UpdateAssetRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateAssetRiskAggregation'
type ScanStatisticsService_UpdateAssetRiskAggregation_Call struct {
	*mock.Call
}

// UpdateAssetRiskAggregation is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - begin time.Time
//   - end time.Time
//   - updateProject bool
func (_e *ScanStatisticsService_Expecter) UpdateAssetRiskAggregation(assetID interface{}, begin interface{}, end interface{}, updateProject interface{}) *ScanStatisticsService_UpdateAssetRiskAggregation_Call {
	return &ScanStatisticsService_UpdateAssetRiskAggregation_Call{Call: _e.mock.On("UpdateAssetRiskAggregation", assetID, begin, end, updateProject)}
}

func (_c *ScanStatisticsService_UpdateAssetRiskAggregation_Call) Run(run func(assetID uuid.UUID, begin time.Time, end time.Time, updateProject bool)) *ScanStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time), args[2].(time.Time), args[3].(bool))
	})
	return _c
}

func (_c *ScanStatisticsService_UpdateAssetRiskAggregation_Call) Return(_a0 error) *ScanStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ScanStatisticsService_UpdateAssetRiskAggregation_Call) RunAndReturn(run func(uuid.UUID, time.Time, time.Time, bool) error) *ScanStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}

// NewScanStatisticsService creates a new instance of ScanStatisticsService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewScanStatisticsService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ScanStatisticsService {
	mock := &ScanStatisticsService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}