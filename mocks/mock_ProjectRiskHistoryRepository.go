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

// GetRiskHistory provides a mock function for the type ProjectRiskHistoryRepository
func (_mock *ProjectRiskHistoryRepository) GetRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	ret := _mock.Called(projectID, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistory")
	}

	var r0 []models.ProjectRiskHistory
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) ([]models.ProjectRiskHistory, error)); ok {
		return returnFunc(projectID, start, end)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) []models.ProjectRiskHistory); ok {
		r0 = returnFunc(projectID, start, end)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ProjectRiskHistory)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID, time.Time, time.Time) error); ok {
		r1 = returnFunc(projectID, start, end)
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
//   - projectID uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *ProjectRiskHistoryRepository_Expecter) GetRiskHistory(projectID interface{}, start interface{}, end interface{}) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	return &ProjectRiskHistoryRepository_GetRiskHistory_Call{Call: _e.mock.On("GetRiskHistory", projectID, start, end)}
}

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) Run(run func(projectID uuid.UUID, start time.Time, end time.Time)) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 uuid.UUID
		if args[0] != nil {
			arg0 = args[0].(uuid.UUID)
		}
		var arg1 time.Time
		if args[1] != nil {
			arg1 = args[1].(time.Time)
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

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) Return(projectRiskHistorys []models.ProjectRiskHistory, err error) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(projectRiskHistorys, err)
	return _c
}

func (_c *ProjectRiskHistoryRepository_GetRiskHistory_Call) RunAndReturn(run func(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error)) *ProjectRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRiskAggregation provides a mock function for the type ProjectRiskHistoryRepository
func (_mock *ProjectRiskHistoryRepository) UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error {
	ret := _mock.Called(projectRisk)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRiskAggregation")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(*models.ProjectRiskHistory) error); ok {
		r0 = returnFunc(projectRisk)
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
		var arg0 *models.ProjectRiskHistory
		if args[0] != nil {
			arg0 = args[0].(*models.ProjectRiskHistory)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call) Return(err error) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call) RunAndReturn(run func(projectRisk *models.ProjectRiskHistory) error) *ProjectRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}
