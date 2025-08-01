// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/openvex/go-vex/pkg/vex"
	mock "github.com/stretchr/testify/mock"
)

// NewAssetVersionService creates a new instance of AssetVersionService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetVersionService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetVersionService {
	mock := &AssetVersionService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// AssetVersionService is an autogenerated mock type for the AssetVersionService type
type AssetVersionService struct {
	mock.Mock
}

type AssetVersionService_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetVersionService) EXPECT() *AssetVersionService_Expecter {
	return &AssetVersionService_Expecter{mock: &_m.Mock}
}

// BuildOpenVeX provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) BuildOpenVeX(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX {
	ret := _mock.Called(asset, assetVersion, organizationSlug, dependencyVulns)

	if len(ret) == 0 {
		panic("no return value specified for BuildOpenVeX")
	}

	var r0 vex.VEX
	if returnFunc, ok := ret.Get(0).(func(models.Asset, models.AssetVersion, string, []models.DependencyVuln) vex.VEX); ok {
		r0 = returnFunc(asset, assetVersion, organizationSlug, dependencyVulns)
	} else {
		r0 = ret.Get(0).(vex.VEX)
	}
	return r0
}

// AssetVersionService_BuildOpenVeX_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildOpenVeX'
type AssetVersionService_BuildOpenVeX_Call struct {
	*mock.Call
}

// BuildOpenVeX is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion models.AssetVersion
//   - organizationSlug string
//   - dependencyVulns []models.DependencyVuln
func (_e *AssetVersionService_Expecter) BuildOpenVeX(asset interface{}, assetVersion interface{}, organizationSlug interface{}, dependencyVulns interface{}) *AssetVersionService_BuildOpenVeX_Call {
	return &AssetVersionService_BuildOpenVeX_Call{Call: _e.mock.On("BuildOpenVeX", asset, assetVersion, organizationSlug, dependencyVulns)}
}

func (_c *AssetVersionService_BuildOpenVeX_Call) Run(run func(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln)) *AssetVersionService_BuildOpenVeX_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Asset
		if args[0] != nil {
			arg0 = args[0].(models.Asset)
		}
		var arg1 models.AssetVersion
		if args[1] != nil {
			arg1 = args[1].(models.AssetVersion)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		var arg3 []models.DependencyVuln
		if args[3] != nil {
			arg3 = args[3].([]models.DependencyVuln)
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

func (_c *AssetVersionService_BuildOpenVeX_Call) Return(vEX vex.VEX) *AssetVersionService_BuildOpenVeX_Call {
	_c.Call.Return(vEX)
	return _c
}

func (_c *AssetVersionService_BuildOpenVeX_Call) RunAndReturn(run func(asset models.Asset, assetVersion models.AssetVersion, organizationSlug string, dependencyVulns []models.DependencyVuln) vex.VEX) *AssetVersionService_BuildOpenVeX_Call {
	_c.Call.Return(run)
	return _c
}

// BuildSBOM provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) BuildSBOM(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency) *cyclonedx.BOM {
	ret := _mock.Called(assetVersion, version, orgName, components)

	if len(ret) == 0 {
		panic("no return value specified for BuildSBOM")
	}

	var r0 *cyclonedx.BOM
	if returnFunc, ok := ret.Get(0).(func(models.AssetVersion, string, string, []models.ComponentDependency) *cyclonedx.BOM); ok {
		r0 = returnFunc(assetVersion, version, orgName, components)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*cyclonedx.BOM)
		}
	}
	return r0
}

// AssetVersionService_BuildSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildSBOM'
type AssetVersionService_BuildSBOM_Call struct {
	*mock.Call
}

// BuildSBOM is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
//   - version string
//   - orgName string
//   - components []models.ComponentDependency
func (_e *AssetVersionService_Expecter) BuildSBOM(assetVersion interface{}, version interface{}, orgName interface{}, components interface{}) *AssetVersionService_BuildSBOM_Call {
	return &AssetVersionService_BuildSBOM_Call{Call: _e.mock.On("BuildSBOM", assetVersion, version, orgName, components)}
}

func (_c *AssetVersionService_BuildSBOM_Call) Run(run func(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency)) *AssetVersionService_BuildSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.AssetVersion
		if args[0] != nil {
			arg0 = args[0].(models.AssetVersion)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		var arg3 []models.ComponentDependency
		if args[3] != nil {
			arg3 = args[3].([]models.ComponentDependency)
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

func (_c *AssetVersionService_BuildSBOM_Call) Return(bOM *cyclonedx.BOM) *AssetVersionService_BuildSBOM_Call {
	_c.Call.Return(bOM)
	return _c
}

func (_c *AssetVersionService_BuildSBOM_Call) RunAndReturn(run func(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency) *cyclonedx.BOM) *AssetVersionService_BuildSBOM_Call {
	_c.Call.Return(run)
	return _c
}

// BuildVeX provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, orgName string, dependencyVulns []models.DependencyVuln) *cyclonedx.BOM {
	ret := _mock.Called(asset, assetVersion, orgName, dependencyVulns)

	if len(ret) == 0 {
		panic("no return value specified for BuildVeX")
	}

	var r0 *cyclonedx.BOM
	if returnFunc, ok := ret.Get(0).(func(models.Asset, models.AssetVersion, string, []models.DependencyVuln) *cyclonedx.BOM); ok {
		r0 = returnFunc(asset, assetVersion, orgName, dependencyVulns)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*cyclonedx.BOM)
		}
	}
	return r0
}

// AssetVersionService_BuildVeX_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildVeX'
type AssetVersionService_BuildVeX_Call struct {
	*mock.Call
}

// BuildVeX is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion models.AssetVersion
//   - orgName string
//   - dependencyVulns []models.DependencyVuln
func (_e *AssetVersionService_Expecter) BuildVeX(asset interface{}, assetVersion interface{}, orgName interface{}, dependencyVulns interface{}) *AssetVersionService_BuildVeX_Call {
	return &AssetVersionService_BuildVeX_Call{Call: _e.mock.On("BuildVeX", asset, assetVersion, orgName, dependencyVulns)}
}

func (_c *AssetVersionService_BuildVeX_Call) Run(run func(asset models.Asset, assetVersion models.AssetVersion, orgName string, dependencyVulns []models.DependencyVuln)) *AssetVersionService_BuildVeX_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Asset
		if args[0] != nil {
			arg0 = args[0].(models.Asset)
		}
		var arg1 models.AssetVersion
		if args[1] != nil {
			arg1 = args[1].(models.AssetVersion)
		}
		var arg2 string
		if args[2] != nil {
			arg2 = args[2].(string)
		}
		var arg3 []models.DependencyVuln
		if args[3] != nil {
			arg3 = args[3].([]models.DependencyVuln)
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

func (_c *AssetVersionService_BuildVeX_Call) Return(bOM *cyclonedx.BOM) *AssetVersionService_BuildVeX_Call {
	_c.Call.Return(bOM)
	return _c
}

func (_c *AssetVersionService_BuildVeX_Call) RunAndReturn(run func(asset models.Asset, assetVersion models.AssetVersion, orgName string, dependencyVulns []models.DependencyVuln) *cyclonedx.BOM) *AssetVersionService_BuildVeX_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetVersionsByAssetID provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	ret := _mock.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetVersionsByAssetID")
	}

	var r0 []models.AssetVersion
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) ([]models.AssetVersion, error)); ok {
		return returnFunc(assetID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) []models.AssetVersion); ok {
		r0 = returnFunc(assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(assetID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// AssetVersionService_GetAssetVersionsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionsByAssetID'
type AssetVersionService_GetAssetVersionsByAssetID_Call struct {
	*mock.Call
}

// GetAssetVersionsByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *AssetVersionService_Expecter) GetAssetVersionsByAssetID(assetID interface{}) *AssetVersionService_GetAssetVersionsByAssetID_Call {
	return &AssetVersionService_GetAssetVersionsByAssetID_Call{Call: _e.mock.On("GetAssetVersionsByAssetID", assetID)}
}

func (_c *AssetVersionService_GetAssetVersionsByAssetID_Call) Run(run func(assetID uuid.UUID)) *AssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 uuid.UUID
		if args[0] != nil {
			arg0 = args[0].(uuid.UUID)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *AssetVersionService_GetAssetVersionsByAssetID_Call) Return(assetVersions []models.AssetVersion, err error) *AssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(assetVersions, err)
	return _c
}

func (_c *AssetVersionService_GetAssetVersionsByAssetID_Call) RunAndReturn(run func(assetID uuid.UUID) ([]models.AssetVersion, error)) *AssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// HandleFirstPartyVulnResult provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) HandleFirstPartyVulnResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan common.SarifResult, scannerID string, userID string) (int, int, []models.FirstPartyVuln, error) {
	ret := _mock.Called(org, project, asset, assetVersion, sarifScan, scannerID, userID)

	if len(ret) == 0 {
		panic("no return value specified for HandleFirstPartyVulnResult")
	}

	var r0 int
	var r1 int
	var r2 []models.FirstPartyVuln
	var r3 error
	if returnFunc, ok := ret.Get(0).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, common.SarifResult, string, string) (int, int, []models.FirstPartyVuln, error)); ok {
		return returnFunc(org, project, asset, assetVersion, sarifScan, scannerID, userID)
	}
	if returnFunc, ok := ret.Get(0).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, common.SarifResult, string, string) int); ok {
		r0 = returnFunc(org, project, asset, assetVersion, sarifScan, scannerID, userID)
	} else {
		r0 = ret.Get(0).(int)
	}
	if returnFunc, ok := ret.Get(1).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, common.SarifResult, string, string) int); ok {
		r1 = returnFunc(org, project, asset, assetVersion, sarifScan, scannerID, userID)
	} else {
		r1 = ret.Get(1).(int)
	}
	if returnFunc, ok := ret.Get(2).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, common.SarifResult, string, string) []models.FirstPartyVuln); ok {
		r2 = returnFunc(org, project, asset, assetVersion, sarifScan, scannerID, userID)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).([]models.FirstPartyVuln)
		}
	}
	if returnFunc, ok := ret.Get(3).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, common.SarifResult, string, string) error); ok {
		r3 = returnFunc(org, project, asset, assetVersion, sarifScan, scannerID, userID)
	} else {
		r3 = ret.Error(3)
	}
	return r0, r1, r2, r3
}

// AssetVersionService_HandleFirstPartyVulnResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleFirstPartyVulnResult'
type AssetVersionService_HandleFirstPartyVulnResult_Call struct {
	*mock.Call
}

// HandleFirstPartyVulnResult is a helper method to define mock.On call
//   - org models.Org
//   - project models.Project
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - sarifScan common.SarifResult
//   - scannerID string
//   - userID string
func (_e *AssetVersionService_Expecter) HandleFirstPartyVulnResult(org interface{}, project interface{}, asset interface{}, assetVersion interface{}, sarifScan interface{}, scannerID interface{}, userID interface{}) *AssetVersionService_HandleFirstPartyVulnResult_Call {
	return &AssetVersionService_HandleFirstPartyVulnResult_Call{Call: _e.mock.On("HandleFirstPartyVulnResult", org, project, asset, assetVersion, sarifScan, scannerID, userID)}
}

func (_c *AssetVersionService_HandleFirstPartyVulnResult_Call) Run(run func(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan common.SarifResult, scannerID string, userID string)) *AssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Org
		if args[0] != nil {
			arg0 = args[0].(models.Org)
		}
		var arg1 models.Project
		if args[1] != nil {
			arg1 = args[1].(models.Project)
		}
		var arg2 models.Asset
		if args[2] != nil {
			arg2 = args[2].(models.Asset)
		}
		var arg3 *models.AssetVersion
		if args[3] != nil {
			arg3 = args[3].(*models.AssetVersion)
		}
		var arg4 common.SarifResult
		if args[4] != nil {
			arg4 = args[4].(common.SarifResult)
		}
		var arg5 string
		if args[5] != nil {
			arg5 = args[5].(string)
		}
		var arg6 string
		if args[6] != nil {
			arg6 = args[6].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
			arg4,
			arg5,
			arg6,
		)
	})
	return _c
}

func (_c *AssetVersionService_HandleFirstPartyVulnResult_Call) Return(n int, n1 int, firstPartyVulns []models.FirstPartyVuln, err error) *AssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(n, n1, firstPartyVulns, err)
	return _c
}

func (_c *AssetVersionService_HandleFirstPartyVulnResult_Call) RunAndReturn(run func(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, sarifScan common.SarifResult, scannerID string, userID string) (int, int, []models.FirstPartyVuln, error)) *AssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(run)
	return _c
}

// HandleScanResult provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) HandleScanResult(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scannerID string, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	ret := _mock.Called(org, project, asset, assetVersion, vulns, scannerID, userID)

	if len(ret) == 0 {
		panic("no return value specified for HandleScanResult")
	}

	var r0 []models.DependencyVuln
	var r1 []models.DependencyVuln
	var r2 []models.DependencyVuln
	var r3 error
	if returnFunc, ok := ret.Get(0).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error)); ok {
		return returnFunc(org, project, asset, assetVersion, vulns, scannerID, userID)
	}
	if returnFunc, ok := ret.Get(0).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string) []models.DependencyVuln); ok {
		r0 = returnFunc(org, project, asset, assetVersion, vulns, scannerID, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string) []models.DependencyVuln); ok {
		r1 = returnFunc(org, project, asset, assetVersion, vulns, scannerID, userID)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]models.DependencyVuln)
		}
	}
	if returnFunc, ok := ret.Get(2).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string) []models.DependencyVuln); ok {
		r2 = returnFunc(org, project, asset, assetVersion, vulns, scannerID, userID)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).([]models.DependencyVuln)
		}
	}
	if returnFunc, ok := ret.Get(3).(func(models.Org, models.Project, models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string) error); ok {
		r3 = returnFunc(org, project, asset, assetVersion, vulns, scannerID, userID)
	} else {
		r3 = ret.Error(3)
	}
	return r0, r1, r2, r3
}

// AssetVersionService_HandleScanResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleScanResult'
type AssetVersionService_HandleScanResult_Call struct {
	*mock.Call
}

// HandleScanResult is a helper method to define mock.On call
//   - org models.Org
//   - project models.Project
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - vulns []models.VulnInPackage
//   - scannerID string
//   - userID string
func (_e *AssetVersionService_Expecter) HandleScanResult(org interface{}, project interface{}, asset interface{}, assetVersion interface{}, vulns interface{}, scannerID interface{}, userID interface{}) *AssetVersionService_HandleScanResult_Call {
	return &AssetVersionService_HandleScanResult_Call{Call: _e.mock.On("HandleScanResult", org, project, asset, assetVersion, vulns, scannerID, userID)}
}

func (_c *AssetVersionService_HandleScanResult_Call) Run(run func(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scannerID string, userID string)) *AssetVersionService_HandleScanResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Org
		if args[0] != nil {
			arg0 = args[0].(models.Org)
		}
		var arg1 models.Project
		if args[1] != nil {
			arg1 = args[1].(models.Project)
		}
		var arg2 models.Asset
		if args[2] != nil {
			arg2 = args[2].(models.Asset)
		}
		var arg3 *models.AssetVersion
		if args[3] != nil {
			arg3 = args[3].(*models.AssetVersion)
		}
		var arg4 []models.VulnInPackage
		if args[4] != nil {
			arg4 = args[4].([]models.VulnInPackage)
		}
		var arg5 string
		if args[5] != nil {
			arg5 = args[5].(string)
		}
		var arg6 string
		if args[6] != nil {
			arg6 = args[6].(string)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
			arg4,
			arg5,
			arg6,
		)
	})
	return _c
}

func (_c *AssetVersionService_HandleScanResult_Call) Return(opened []models.DependencyVuln, closed []models.DependencyVuln, newState []models.DependencyVuln, err error) *AssetVersionService_HandleScanResult_Call {
	_c.Call.Return(opened, closed, newState, err)
	return _c
}

func (_c *AssetVersionService_HandleScanResult_Call) RunAndReturn(run func(org models.Org, project models.Project, asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scannerID string, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error)) *AssetVersionService_HandleScanResult_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateSBOM provides a mock function for the type AssetVersionService
func (_mock *AssetVersionService) UpdateSBOM(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM) error {
	ret := _mock.Called(org, project, asset, assetVersion, scannerID, sbom)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSBOM")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(models.Org, models.Project, models.Asset, models.AssetVersion, string, normalize.SBOM) error); ok {
		r0 = returnFunc(org, project, asset, assetVersion, scannerID, sbom)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// AssetVersionService_UpdateSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateSBOM'
type AssetVersionService_UpdateSBOM_Call struct {
	*mock.Call
}

// UpdateSBOM is a helper method to define mock.On call
//   - org models.Org
//   - project models.Project
//   - asset models.Asset
//   - assetVersion models.AssetVersion
//   - scannerID string
//   - sbom normalize.SBOM
func (_e *AssetVersionService_Expecter) UpdateSBOM(org interface{}, project interface{}, asset interface{}, assetVersion interface{}, scannerID interface{}, sbom interface{}) *AssetVersionService_UpdateSBOM_Call {
	return &AssetVersionService_UpdateSBOM_Call{Call: _e.mock.On("UpdateSBOM", org, project, asset, assetVersion, scannerID, sbom)}
}

func (_c *AssetVersionService_UpdateSBOM_Call) Run(run func(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM)) *AssetVersionService_UpdateSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 models.Org
		if args[0] != nil {
			arg0 = args[0].(models.Org)
		}
		var arg1 models.Project
		if args[1] != nil {
			arg1 = args[1].(models.Project)
		}
		var arg2 models.Asset
		if args[2] != nil {
			arg2 = args[2].(models.Asset)
		}
		var arg3 models.AssetVersion
		if args[3] != nil {
			arg3 = args[3].(models.AssetVersion)
		}
		var arg4 string
		if args[4] != nil {
			arg4 = args[4].(string)
		}
		var arg5 normalize.SBOM
		if args[5] != nil {
			arg5 = args[5].(normalize.SBOM)
		}
		run(
			arg0,
			arg1,
			arg2,
			arg3,
			arg4,
			arg5,
		)
	})
	return _c
}

func (_c *AssetVersionService_UpdateSBOM_Call) Return(err error) *AssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *AssetVersionService_UpdateSBOM_Call) RunAndReturn(run func(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM) error) *AssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(run)
	return _c
}
