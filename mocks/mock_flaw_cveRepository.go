// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// FlawCveRepository is an autogenerated mock type for the cveRepository type
type FlawCveRepository struct {
	mock.Mock
}

type FlawCveRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *FlawCveRepository) EXPECT() *FlawCveRepository_Expecter {
	return &FlawCveRepository_Expecter{mock: &_m.Mock}
}

// FindCVE provides a mock function with given fields: tx, cveId
func (_m *FlawCveRepository) FindCVE(tx *gorm.DB, cveId string) (models.CVE, error) {
	ret := _m.Called(tx, cveId)

	if len(ret) == 0 {
		panic("no return value specified for FindCVE")
	}

	var r0 models.CVE
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) (models.CVE, error)); ok {
		return rf(tx, cveId)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) models.CVE); ok {
		r0 = rf(tx, cveId)
	} else {
		r0 = ret.Get(0).(models.CVE)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string) error); ok {
		r1 = rf(tx, cveId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawCveRepository_FindCVE_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindCVE'
type FlawCveRepository_FindCVE_Call struct {
	*mock.Call
}

// FindCVE is a helper method to define mock.On call
//   - tx *gorm.DB
//   - cveId string
func (_e *FlawCveRepository_Expecter) FindCVE(tx interface{}, cveId interface{}) *FlawCveRepository_FindCVE_Call {
	return &FlawCveRepository_FindCVE_Call{Call: _e.mock.On("FindCVE", tx, cveId)}
}

func (_c *FlawCveRepository_FindCVE_Call) Run(run func(tx *gorm.DB, cveId string)) *FlawCveRepository_FindCVE_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *FlawCveRepository_FindCVE_Call) Return(_a0 models.CVE, _a1 error) *FlawCveRepository_FindCVE_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawCveRepository_FindCVE_Call) RunAndReturn(run func(*gorm.DB, string) (models.CVE, error)) *FlawCveRepository_FindCVE_Call {
	_c.Call.Return(run)
	return _c
}

// FindCVEs provides a mock function with given fields: tx, cveIds
func (_m *FlawCveRepository) FindCVEs(tx *gorm.DB, cveIds []string) ([]models.CVE, error) {
	ret := _m.Called(tx, cveIds)

	if len(ret) == 0 {
		panic("no return value specified for FindCVEs")
	}

	var r0 []models.CVE
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string) ([]models.CVE, error)); ok {
		return rf(tx, cveIds)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string) []models.CVE); ok {
		r0 = rf(tx, cveIds)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.CVE)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, []string) error); ok {
		r1 = rf(tx, cveIds)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawCveRepository_FindCVEs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindCVEs'
type FlawCveRepository_FindCVEs_Call struct {
	*mock.Call
}

// FindCVEs is a helper method to define mock.On call
//   - tx *gorm.DB
//   - cveIds []string
func (_e *FlawCveRepository_Expecter) FindCVEs(tx interface{}, cveIds interface{}) *FlawCveRepository_FindCVEs_Call {
	return &FlawCveRepository_FindCVEs_Call{Call: _e.mock.On("FindCVEs", tx, cveIds)}
}

func (_c *FlawCveRepository_FindCVEs_Call) Run(run func(tx *gorm.DB, cveIds []string)) *FlawCveRepository_FindCVEs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]string))
	})
	return _c
}

func (_c *FlawCveRepository_FindCVEs_Call) Return(_a0 []models.CVE, _a1 error) *FlawCveRepository_FindCVEs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawCveRepository_FindCVEs_Call) RunAndReturn(run func(*gorm.DB, []string) ([]models.CVE, error)) *FlawCveRepository_FindCVEs_Call {
	_c.Call.Return(run)
	return _c
}

// NewFlawCveRepository creates a new instance of FlawCveRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlawCveRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *FlawCveRepository {
	mock := &FlawCveRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
