// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	time "time"

	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// ProjectRiskHistoryRepository is an autogenerated mock type for the ProjectRiskHistoryRepository type
type ProjectRiskHistoryRepository struct {
	mock.Mock
}

type ProjectRiskHistoryRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ProjectRiskHistoryRepository) EXPECT() *ProjectRiskHistoryRepository_Expecter {
	return &ProjectRiskHistoryRepository_Expecter{mock: &_m.Mock}
}

// GetRiskHistory provides a mock function with given fields: projectId, start, end
func (_m *ProjectRiskHistoryRepository) GetRiskHistory(projectId uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	ret := _m.Called(projectId, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistory")
	}

	var r0 []models.ProjectRiskHistory
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) ([]models.ProjectRiskHistory, error)); ok {
		return rf(projectId, start, end)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) []models.ProjectRiskHistory); ok {
		r0 = rf(projectId, start, end)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ProjectRiskHistory)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, time.Time, time.Time) error); ok {
		r1 = rf(projectId, start, end)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectRiskHistoryRepository_GetRiskHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRiskHistory'
type ProjectRiskHistoryRepository_GetRiskHistory_Call struct {
	*mock.Call
}

// GetRiskHistory is a helper method to define mock.On call
//   - projectId uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *ProjectRiskHistoryRepository_Expecter) GetRiskHistory(projectId interface{}, start interface{}, end interface{}) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	return &ProjectRiskHistoryRepository_GetRiskHistory_Call{Call: _e.mock.On("GetRiskHistory", projectId, start, end)}
}

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) Run(run func(projectId uuid.UUID, start time.Time, end time.Time)) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time), args[2].(time.Time))
	})
	return _c
}

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) Return(_a0 []models.ProjectRiskHistory, _a1 error) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) RunAndReturn(run func(uuid.UUID, time.Time, time.Time) ([]models.ProjectRiskHistory, error)) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRiskAggregation provides a mock function with given fields: projectRisk
func (_m *ProjectRiskHistoryRepository) UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error {
	ret := _m.Called(projectRisk)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRiskAggregation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*models.ProjectRiskHistory) error); ok {
		r0 = rf(projectRisk)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProjectRiskHistoryRepository_UpdateRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateRiskAggregation'
type ProjectRiskHistoryRepository_UpdateRiskAggregation_Call struct {
	*mock.Call
}

// UpdateRiskAggregation is a helper method to define mock.On call
//   - projectRisk *models.ProjectRiskHistory
func (_e *ProjectRiskHistoryRepository_Expecter) UpdateRiskAggregation(projectRisk interface{}) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	return &ProjectRiskHistoryRepository_UpdateRiskAggregation_Call{Call: _e.mock.On("UpdateRiskAggregation", projectRisk)}
}

func (_c *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call) Run(run func(projectRisk *models.ProjectRiskHistory)) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*models.ProjectRiskHistory))
	})
	return _c
}

func (_c *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call) Return(_a0 error) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call) RunAndReturn(run func(*models.ProjectRiskHistory) error) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}

// NewProjectRiskHistoryRepository creates a new instance of ProjectRiskHistoryRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProjectRiskHistoryRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProjectRiskHistoryRepository {
	mock := &ProjectRiskHistoryRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
