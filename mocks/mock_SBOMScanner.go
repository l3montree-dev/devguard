// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// NewSBOMScanner creates a new instance of SBOMScanner. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSBOMScanner(t interface {
	mock.TestingT
	Cleanup(func())
}) *SBOMScanner {
	mock := &SBOMScanner{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// SBOMScanner is an autogenerated mock type for the SBOMScanner type
type SBOMScanner struct {
	mock.Mock
}

type SBOMScanner_Expecter struct {
	mock *mock.Mock
}

func (_m *SBOMScanner) EXPECT() *SBOMScanner_Expecter {
	return &SBOMScanner_Expecter{mock: &_m.Mock}
}

// Scan provides a mock function for the type SBOMScanner
func (_mock *SBOMScanner) Scan(bom normalize.SBOM) ([]models.VulnInPackage, error) {
	ret := _mock.Called(bom)

	if len(ret) == 0 {
		panic("no return value specified for Scan")
	}

	var r0 []models.VulnInPackage
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(normalize.SBOM) ([]models.VulnInPackage, error)); ok {
		return returnFunc(bom)
	}
	if returnFunc, ok := ret.Get(0).(func(normalize.SBOM) []models.VulnInPackage); ok {
		r0 = returnFunc(bom)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.VulnInPackage)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(normalize.SBOM) error); ok {
		r1 = returnFunc(bom)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// SBOMScanner_Scan_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Scan'
type SBOMScanner_Scan_Call struct {
	*mock.Call
}

// Scan is a helper method to define mock.On call
//   - bom normalize.SBOM
func (_e *SBOMScanner_Expecter) Scan(bom interface{}) *SBOMScanner_Scan_Call {
	return &SBOMScanner_Scan_Call{Call: _e.mock.On("Scan", bom)}
}

func (_c *SBOMScanner_Scan_Call) Run(run func(bom normalize.SBOM)) *SBOMScanner_Scan_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 normalize.SBOM
		if args[0] != nil {
			arg0 = args[0].(normalize.SBOM)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *SBOMScanner_Scan_Call) Return(vulnInPackages []models.VulnInPackage, err error) *SBOMScanner_Scan_Call {
	_c.Call.Return(vulnInPackages, err)
	return _c
}

func (_c *SBOMScanner_Scan_Call) RunAndReturn(run func(bom normalize.SBOM) ([]models.VulnInPackage, error)) *SBOMScanner_Scan_Call {
	_c.Call.Return(run)
	return _c
}
