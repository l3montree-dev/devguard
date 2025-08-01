// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify

package mocks

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	"gorm.io/gorm/clause"
)

// NewProjectRepository creates a new instance of ProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProjectRepository {
	mock := &ProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// ProjectRepository is an autogenerated mock type for the ProjectRepository type
type ProjectRepository struct {
	mock.Mock
}

type ProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ProjectRepository) EXPECT() *ProjectRepository_Expecter {
	return &ProjectRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Activate(tx core.DB, projectID uuid.UUID) error {
	ret := _mock.Called(tx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID) error); ok {
		r0 = returnFunc(tx, projectID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type ProjectRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx core.DB
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) Activate(tx interface{}, projectID interface{}) *ProjectRepository_Activate_Call {
	return &ProjectRepository_Activate_Call{Call: _e.mock.On("Activate", tx, projectID)}
}

func (_c *ProjectRepository_Activate_Call) Run(run func(tx core.DB, projectID uuid.UUID)) *ProjectRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
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

func (_c *ProjectRepository_Activate_Call) Return(err error) *ProjectRepository_Activate_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_Activate_Call) RunAndReturn(run func(tx core.DB, projectID uuid.UUID) error) *ProjectRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Create(tx core.DB, project *models.Project) error {
	ret := _mock.Called(tx, project)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, *models.Project) error); ok {
		r0 = returnFunc(tx, project)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type ProjectRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx core.DB
//   - project *models.Project
func (_e *ProjectRepository_Expecter) Create(tx interface{}, project interface{}) *ProjectRepository_Create_Call {
	return &ProjectRepository_Create_Call{Call: _e.mock.On("Create", tx, project)}
}

func (_c *ProjectRepository_Create_Call) Run(run func(tx core.DB, project *models.Project)) *ProjectRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 *models.Project
		if args[1] != nil {
			arg1 = args[1].(*models.Project)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ProjectRepository_Create_Call) Return(err error) *ProjectRepository_Create_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_Create_Call) RunAndReturn(run func(tx core.DB, project *models.Project) error) *ProjectRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Delete(tx core.DB, projectID uuid.UUID) error {
	ret := _mock.Called(tx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID) error); ok {
		r0 = returnFunc(tx, projectID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type ProjectRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx core.DB
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) Delete(tx interface{}, projectID interface{}) *ProjectRepository_Delete_Call {
	return &ProjectRepository_Delete_Call{Call: _e.mock.On("Delete", tx, projectID)}
}

func (_c *ProjectRepository_Delete_Call) Run(run func(tx core.DB, projectID uuid.UUID)) *ProjectRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
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

func (_c *ProjectRepository_Delete_Call) Return(err error) *ProjectRepository_Delete_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_Delete_Call) RunAndReturn(run func(tx core.DB, projectID uuid.UUID) error) *ProjectRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// DisablePolicyForProject provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) DisablePolicyForProject(tx core.DB, projectID uuid.UUID, policyID uuid.UUID) error {
	ret := _mock.Called(tx, projectID, policyID)

	if len(ret) == 0 {
		panic("no return value specified for DisablePolicyForProject")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID, uuid.UUID) error); ok {
		r0 = returnFunc(tx, projectID, policyID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_DisablePolicyForProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DisablePolicyForProject'
type ProjectRepository_DisablePolicyForProject_Call struct {
	*mock.Call
}

// DisablePolicyForProject is a helper method to define mock.On call
//   - tx core.DB
//   - projectID uuid.UUID
//   - policyID uuid.UUID
func (_e *ProjectRepository_Expecter) DisablePolicyForProject(tx interface{}, projectID interface{}, policyID interface{}) *ProjectRepository_DisablePolicyForProject_Call {
	return &ProjectRepository_DisablePolicyForProject_Call{Call: _e.mock.On("DisablePolicyForProject", tx, projectID, policyID)}
}

func (_c *ProjectRepository_DisablePolicyForProject_Call) Run(run func(tx core.DB, projectID uuid.UUID, policyID uuid.UUID)) *ProjectRepository_DisablePolicyForProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		var arg2 uuid.UUID
		if args[2] != nil {
			arg2 = args[2].(uuid.UUID)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ProjectRepository_DisablePolicyForProject_Call) Return(err error) *ProjectRepository_DisablePolicyForProject_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_DisablePolicyForProject_Call) RunAndReturn(run func(tx core.DB, projectID uuid.UUID, policyID uuid.UUID) error) *ProjectRepository_DisablePolicyForProject_Call {
	_c.Call.Return(run)
	return _c
}

// EnableCommunityManagedPolicies provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) EnableCommunityManagedPolicies(tx core.DB, projectID uuid.UUID) error {
	ret := _mock.Called(tx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for EnableCommunityManagedPolicies")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID) error); ok {
		r0 = returnFunc(tx, projectID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_EnableCommunityManagedPolicies_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EnableCommunityManagedPolicies'
type ProjectRepository_EnableCommunityManagedPolicies_Call struct {
	*mock.Call
}

// EnableCommunityManagedPolicies is a helper method to define mock.On call
//   - tx core.DB
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) EnableCommunityManagedPolicies(tx interface{}, projectID interface{}) *ProjectRepository_EnableCommunityManagedPolicies_Call {
	return &ProjectRepository_EnableCommunityManagedPolicies_Call{Call: _e.mock.On("EnableCommunityManagedPolicies", tx, projectID)}
}

func (_c *ProjectRepository_EnableCommunityManagedPolicies_Call) Run(run func(tx core.DB, projectID uuid.UUID)) *ProjectRepository_EnableCommunityManagedPolicies_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
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

func (_c *ProjectRepository_EnableCommunityManagedPolicies_Call) Return(err error) *ProjectRepository_EnableCommunityManagedPolicies_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_EnableCommunityManagedPolicies_Call) RunAndReturn(run func(tx core.DB, projectID uuid.UUID) error) *ProjectRepository_EnableCommunityManagedPolicies_Call {
	_c.Call.Return(run)
	return _c
}

// EnablePolicyForProject provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) EnablePolicyForProject(tx core.DB, projectID uuid.UUID, policyID uuid.UUID) error {
	ret := _mock.Called(tx, projectID, policyID)

	if len(ret) == 0 {
		panic("no return value specified for EnablePolicyForProject")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID, uuid.UUID) error); ok {
		r0 = returnFunc(tx, projectID, policyID)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_EnablePolicyForProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EnablePolicyForProject'
type ProjectRepository_EnablePolicyForProject_Call struct {
	*mock.Call
}

// EnablePolicyForProject is a helper method to define mock.On call
//   - tx core.DB
//   - projectID uuid.UUID
//   - policyID uuid.UUID
func (_e *ProjectRepository_Expecter) EnablePolicyForProject(tx interface{}, projectID interface{}, policyID interface{}) *ProjectRepository_EnablePolicyForProject_Call {
	return &ProjectRepository_EnablePolicyForProject_Call{Call: _e.mock.On("EnablePolicyForProject", tx, projectID, policyID)}
}

func (_c *ProjectRepository_EnablePolicyForProject_Call) Run(run func(tx core.DB, projectID uuid.UUID, policyID uuid.UUID)) *ProjectRepository_EnablePolicyForProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(uuid.UUID)
		}
		var arg2 uuid.UUID
		if args[2] != nil {
			arg2 = args[2].(uuid.UUID)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ProjectRepository_EnablePolicyForProject_Call) Return(err error) *ProjectRepository_EnablePolicyForProject_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_EnablePolicyForProject_Call) RunAndReturn(run func(tx core.DB, projectID uuid.UUID, policyID uuid.UUID) error) *ProjectRepository_EnablePolicyForProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetByOrgID provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) GetByOrgID(organizationID uuid.UUID) ([]models.Project, error) {
	ret := _mock.Called(organizationID)

	if len(ret) == 0 {
		panic("no return value specified for GetByOrgID")
	}

	var r0 []models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return returnFunc(organizationID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = returnFunc(organizationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(organizationID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_GetByOrgID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByOrgID'
type ProjectRepository_GetByOrgID_Call struct {
	*mock.Call
}

// GetByOrgID is a helper method to define mock.On call
//   - organizationID uuid.UUID
func (_e *ProjectRepository_Expecter) GetByOrgID(organizationID interface{}) *ProjectRepository_GetByOrgID_Call {
	return &ProjectRepository_GetByOrgID_Call{Call: _e.mock.On("GetByOrgID", organizationID)}
}

func (_c *ProjectRepository_GetByOrgID_Call) Run(run func(organizationID uuid.UUID)) *ProjectRepository_GetByOrgID_Call {
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

func (_c *ProjectRepository_GetByOrgID_Call) Return(projects []models.Project, err error) *ProjectRepository_GetByOrgID_Call {
	_c.Call.Return(projects, err)
	return _c
}

func (_c *ProjectRepository_GetByOrgID_Call) RunAndReturn(run func(organizationID uuid.UUID) ([]models.Project, error)) *ProjectRepository_GetByOrgID_Call {
	_c.Call.Return(run)
	return _c
}

// GetDirectChildProjects provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	ret := _mock.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetDirectChildProjects")
	}

	var r0 []models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return returnFunc(projectID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = returnFunc(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(projectID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_GetDirectChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDirectChildProjects'
type ProjectRepository_GetDirectChildProjects_Call struct {
	*mock.Call
}

// GetDirectChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) GetDirectChildProjects(projectID interface{}) *ProjectRepository_GetDirectChildProjects_Call {
	return &ProjectRepository_GetDirectChildProjects_Call{Call: _e.mock.On("GetDirectChildProjects", projectID)}
}

func (_c *ProjectRepository_GetDirectChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectRepository_GetDirectChildProjects_Call {
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

func (_c *ProjectRepository_GetDirectChildProjects_Call) Return(projects []models.Project, err error) *ProjectRepository_GetDirectChildProjects_Call {
	_c.Call.Return(projects, err)
	return _c
}

func (_c *ProjectRepository_GetDirectChildProjects_Call) RunAndReturn(run func(projectID uuid.UUID) ([]models.Project, error)) *ProjectRepository_GetDirectChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// GetProjectByAssetID provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) GetProjectByAssetID(assetID uuid.UUID) (models.Project, error) {
	ret := _mock.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectByAssetID")
	}

	var r0 models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) (models.Project, error)); ok {
		return returnFunc(assetID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) models.Project); ok {
		r0 = returnFunc(assetID)
	} else {
		r0 = ret.Get(0).(models.Project)
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(assetID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_GetProjectByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectByAssetID'
type ProjectRepository_GetProjectByAssetID_Call struct {
	*mock.Call
}

// GetProjectByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *ProjectRepository_Expecter) GetProjectByAssetID(assetID interface{}) *ProjectRepository_GetProjectByAssetID_Call {
	return &ProjectRepository_GetProjectByAssetID_Call{Call: _e.mock.On("GetProjectByAssetID", assetID)}
}

func (_c *ProjectRepository_GetProjectByAssetID_Call) Run(run func(assetID uuid.UUID)) *ProjectRepository_GetProjectByAssetID_Call {
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

func (_c *ProjectRepository_GetProjectByAssetID_Call) Return(project models.Project, err error) *ProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(project, err)
	return _c
}

func (_c *ProjectRepository_GetProjectByAssetID_Call) RunAndReturn(run func(assetID uuid.UUID) (models.Project, error)) *ProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) List(idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID) ([]models.Project, error) {
	ret := _mock.Called(idSlice, parentID, organizationID)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) ([]models.Project, error)); ok {
		return returnFunc(idSlice, parentID, organizationID)
	}
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) []models.Project); ok {
		r0 = returnFunc(idSlice, parentID, organizationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) error); ok {
		r1 = returnFunc(idSlice, parentID, organizationID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type ProjectRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - idSlice []uuid.UUID
//   - parentID *uuid.UUID
//   - organizationID uuid.UUID
func (_e *ProjectRepository_Expecter) List(idSlice interface{}, parentID interface{}, organizationID interface{}) *ProjectRepository_List_Call {
	return &ProjectRepository_List_Call{Call: _e.mock.On("List", idSlice, parentID, organizationID)}
}

func (_c *ProjectRepository_List_Call) Run(run func(idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID)) *ProjectRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 []uuid.UUID
		if args[0] != nil {
			arg0 = args[0].([]uuid.UUID)
		}
		var arg1 *uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(*uuid.UUID)
		}
		var arg2 uuid.UUID
		if args[2] != nil {
			arg2 = args[2].(uuid.UUID)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ProjectRepository_List_Call) Return(projects []models.Project, err error) *ProjectRepository_List_Call {
	_c.Call.Return(projects, err)
	return _c
}

func (_c *ProjectRepository_List_Call) RunAndReturn(run func(idSlice []uuid.UUID, parentID *uuid.UUID, organizationID uuid.UUID) ([]models.Project, error)) *ProjectRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// ListPaged provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) ListPaged(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo core.PageInfo, search string) (core.Paged[models.Project], error) {
	ret := _mock.Called(projectIDs, parentID, orgID, pageInfo, search)

	if len(ret) == 0 {
		panic("no return value specified for ListPaged")
	}

	var r0 core.Paged[models.Project]
	var r1 error
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID, core.PageInfo, string) (core.Paged[models.Project], error)); ok {
		return returnFunc(projectIDs, parentID, orgID, pageInfo, search)
	}
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID, core.PageInfo, string) core.Paged[models.Project]); ok {
		r0 = returnFunc(projectIDs, parentID, orgID, pageInfo, search)
	} else {
		r0 = ret.Get(0).(core.Paged[models.Project])
	}
	if returnFunc, ok := ret.Get(1).(func([]uuid.UUID, *uuid.UUID, uuid.UUID, core.PageInfo, string) error); ok {
		r1 = returnFunc(projectIDs, parentID, orgID, pageInfo, search)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_ListPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListPaged'
type ProjectRepository_ListPaged_Call struct {
	*mock.Call
}

// ListPaged is a helper method to define mock.On call
//   - projectIDs []uuid.UUID
//   - parentID *uuid.UUID
//   - orgID uuid.UUID
//   - pageInfo core.PageInfo
//   - search string
func (_e *ProjectRepository_Expecter) ListPaged(projectIDs interface{}, parentID interface{}, orgID interface{}, pageInfo interface{}, search interface{}) *ProjectRepository_ListPaged_Call {
	return &ProjectRepository_ListPaged_Call{Call: _e.mock.On("ListPaged", projectIDs, parentID, orgID, pageInfo, search)}
}

func (_c *ProjectRepository_ListPaged_Call) Run(run func(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo core.PageInfo, search string)) *ProjectRepository_ListPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 []uuid.UUID
		if args[0] != nil {
			arg0 = args[0].([]uuid.UUID)
		}
		var arg1 *uuid.UUID
		if args[1] != nil {
			arg1 = args[1].(*uuid.UUID)
		}
		var arg2 uuid.UUID
		if args[2] != nil {
			arg2 = args[2].(uuid.UUID)
		}
		var arg3 core.PageInfo
		if args[3] != nil {
			arg3 = args[3].(core.PageInfo)
		}
		var arg4 string
		if args[4] != nil {
			arg4 = args[4].(string)
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

func (_c *ProjectRepository_ListPaged_Call) Return(paged core.Paged[models.Project], err error) *ProjectRepository_ListPaged_Call {
	_c.Call.Return(paged, err)
	return _c
}

func (_c *ProjectRepository_ListPaged_Call) RunAndReturn(run func(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo core.PageInfo, search string) (core.Paged[models.Project], error)) *ProjectRepository_ListPaged_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Read(projectID uuid.UUID) (models.Project, error) {
	ret := _mock.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) (models.Project, error)); ok {
		return returnFunc(projectID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) models.Project); ok {
		r0 = returnFunc(projectID)
	} else {
		r0 = ret.Get(0).(models.Project)
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(projectID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type ProjectRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) Read(projectID interface{}) *ProjectRepository_Read_Call {
	return &ProjectRepository_Read_Call{Call: _e.mock.On("Read", projectID)}
}

func (_c *ProjectRepository_Read_Call) Run(run func(projectID uuid.UUID)) *ProjectRepository_Read_Call {
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

func (_c *ProjectRepository_Read_Call) Return(project models.Project, err error) *ProjectRepository_Read_Call {
	_c.Call.Return(project, err)
	return _c
}

func (_c *ProjectRepository_Read_Call) RunAndReturn(run func(projectID uuid.UUID) (models.Project, error)) *ProjectRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// ReadBySlug provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error) {
	ret := _mock.Called(organizationID, slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlug")
	}

	var r0 models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string) (models.Project, error)); ok {
		return returnFunc(organizationID, slug)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string) models.Project); ok {
		r0 = returnFunc(organizationID, slug)
	} else {
		r0 = ret.Get(0).(models.Project)
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = returnFunc(organizationID, slug)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_ReadBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlug'
type ProjectRepository_ReadBySlug_Call struct {
	*mock.Call
}

// ReadBySlug is a helper method to define mock.On call
//   - organizationID uuid.UUID
//   - slug string
func (_e *ProjectRepository_Expecter) ReadBySlug(organizationID interface{}, slug interface{}) *ProjectRepository_ReadBySlug_Call {
	return &ProjectRepository_ReadBySlug_Call{Call: _e.mock.On("ReadBySlug", organizationID, slug)}
}

func (_c *ProjectRepository_ReadBySlug_Call) Run(run func(organizationID uuid.UUID, slug string)) *ProjectRepository_ReadBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 uuid.UUID
		if args[0] != nil {
			arg0 = args[0].(uuid.UUID)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ProjectRepository_ReadBySlug_Call) Return(project models.Project, err error) *ProjectRepository_ReadBySlug_Call {
	_c.Call.Return(project, err)
	return _c
}

func (_c *ProjectRepository_ReadBySlug_Call) RunAndReturn(run func(organizationID uuid.UUID, slug string) (models.Project, error)) *ProjectRepository_ReadBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// ReadBySlugUnscoped provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) ReadBySlugUnscoped(organizationID uuid.UUID, slug string) (models.Project, error) {
	ret := _mock.Called(organizationID, slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlugUnscoped")
	}

	var r0 models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string) (models.Project, error)); ok {
		return returnFunc(organizationID, slug)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID, string) models.Project); ok {
		r0 = returnFunc(organizationID, slug)
	} else {
		r0 = ret.Get(0).(models.Project)
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = returnFunc(organizationID, slug)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_ReadBySlugUnscoped_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlugUnscoped'
type ProjectRepository_ReadBySlugUnscoped_Call struct {
	*mock.Call
}

// ReadBySlugUnscoped is a helper method to define mock.On call
//   - organizationID uuid.UUID
//   - slug string
func (_e *ProjectRepository_Expecter) ReadBySlugUnscoped(organizationID interface{}, slug interface{}) *ProjectRepository_ReadBySlugUnscoped_Call {
	return &ProjectRepository_ReadBySlugUnscoped_Call{Call: _e.mock.On("ReadBySlugUnscoped", organizationID, slug)}
}

func (_c *ProjectRepository_ReadBySlugUnscoped_Call) Run(run func(organizationID uuid.UUID, slug string)) *ProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 uuid.UUID
		if args[0] != nil {
			arg0 = args[0].(uuid.UUID)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ProjectRepository_ReadBySlugUnscoped_Call) Return(project models.Project, err error) *ProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Return(project, err)
	return _c
}

func (_c *ProjectRepository_ReadBySlugUnscoped_Call) RunAndReturn(run func(organizationID uuid.UUID, slug string) (models.Project, error)) *ProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Return(run)
	return _c
}

// RecursivelyGetChildProjects provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	ret := _mock.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for RecursivelyGetChildProjects")
	}

	var r0 []models.Project
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return returnFunc(projectID)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = returnFunc(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(projectID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ProjectRepository_RecursivelyGetChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecursivelyGetChildProjects'
type ProjectRepository_RecursivelyGetChildProjects_Call struct {
	*mock.Call
}

// RecursivelyGetChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectRepository_Expecter) RecursivelyGetChildProjects(projectID interface{}) *ProjectRepository_RecursivelyGetChildProjects_Call {
	return &ProjectRepository_RecursivelyGetChildProjects_Call{Call: _e.mock.On("RecursivelyGetChildProjects", projectID)}
}

func (_c *ProjectRepository_RecursivelyGetChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectRepository_RecursivelyGetChildProjects_Call {
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

func (_c *ProjectRepository_RecursivelyGetChildProjects_Call) Return(projects []models.Project, err error) *ProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(projects, err)
	return _c
}

func (_c *ProjectRepository_RecursivelyGetChildProjects_Call) RunAndReturn(run func(projectID uuid.UUID) ([]models.Project, error)) *ProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Update(tx core.DB, project *models.Project) error {
	ret := _mock.Called(tx, project)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, *models.Project) error); ok {
		r0 = returnFunc(tx, project)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type ProjectRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - tx core.DB
//   - project *models.Project
func (_e *ProjectRepository_Expecter) Update(tx interface{}, project interface{}) *ProjectRepository_Update_Call {
	return &ProjectRepository_Update_Call{Call: _e.mock.On("Update", tx, project)}
}

func (_c *ProjectRepository_Update_Call) Run(run func(tx core.DB, project *models.Project)) *ProjectRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 *models.Project
		if args[1] != nil {
			arg1 = args[1].(*models.Project)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ProjectRepository_Update_Call) Return(err error) *ProjectRepository_Update_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_Update_Call) RunAndReturn(run func(tx core.DB, project *models.Project) error) *ProjectRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// Upsert provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) Upsert(projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string) error {
	ret := _mock.Called(projects, conflictingColumns, toUpdate)

	if len(ret) == 0 {
		panic("no return value specified for Upsert")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(*[]*models.Project, []clause.Column, []string) error); ok {
		r0 = returnFunc(projects, conflictingColumns, toUpdate)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// ProjectRepository_Upsert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Upsert'
type ProjectRepository_Upsert_Call struct {
	*mock.Call
}

// Upsert is a helper method to define mock.On call
//   - projects *[]*models.Project
//   - conflictingColumns []clause.Column
//   - toUpdate []string
func (_e *ProjectRepository_Expecter) Upsert(projects interface{}, conflictingColumns interface{}, toUpdate interface{}) *ProjectRepository_Upsert_Call {
	return &ProjectRepository_Upsert_Call{Call: _e.mock.On("Upsert", projects, conflictingColumns, toUpdate)}
}

func (_c *ProjectRepository_Upsert_Call) Run(run func(projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string)) *ProjectRepository_Upsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 *[]*models.Project
		if args[0] != nil {
			arg0 = args[0].(*[]*models.Project)
		}
		var arg1 []clause.Column
		if args[1] != nil {
			arg1 = args[1].([]clause.Column)
		}
		var arg2 []string
		if args[2] != nil {
			arg2 = args[2].([]string)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ProjectRepository_Upsert_Call) Return(err error) *ProjectRepository_Upsert_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *ProjectRepository_Upsert_Call) RunAndReturn(run func(projects *[]*models.Project, conflictingColumns []clause.Column, toUpdate []string) error) *ProjectRepository_Upsert_Call {
	_c.Call.Return(run)
	return _c
}

// UpsertSplit provides a mock function for the type ProjectRepository
func (_mock *ProjectRepository) UpsertSplit(tx core.DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error) {
	ret := _mock.Called(tx, externalProviderID, projects)

	if len(ret) == 0 {
		panic("no return value specified for UpsertSplit")
	}

	var r0 []*models.Project
	var r1 []*models.Project
	var r2 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, string, []*models.Project) ([]*models.Project, []*models.Project, error)); ok {
		return returnFunc(tx, externalProviderID, projects)
	}
	if returnFunc, ok := ret.Get(0).(func(core.DB, string, []*models.Project) []*models.Project); ok {
		r0 = returnFunc(tx, externalProviderID, projects)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*models.Project)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(core.DB, string, []*models.Project) []*models.Project); ok {
		r1 = returnFunc(tx, externalProviderID, projects)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]*models.Project)
		}
	}
	if returnFunc, ok := ret.Get(2).(func(core.DB, string, []*models.Project) error); ok {
		r2 = returnFunc(tx, externalProviderID, projects)
	} else {
		r2 = ret.Error(2)
	}
	return r0, r1, r2
}

// ProjectRepository_UpsertSplit_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpsertSplit'
type ProjectRepository_UpsertSplit_Call struct {
	*mock.Call
}

// UpsertSplit is a helper method to define mock.On call
//   - tx core.DB
//   - externalProviderID string
//   - projects []*models.Project
func (_e *ProjectRepository_Expecter) UpsertSplit(tx interface{}, externalProviderID interface{}, projects interface{}) *ProjectRepository_UpsertSplit_Call {
	return &ProjectRepository_UpsertSplit_Call{Call: _e.mock.On("UpsertSplit", tx, externalProviderID, projects)}
}

func (_c *ProjectRepository_UpsertSplit_Call) Run(run func(tx core.DB, externalProviderID string, projects []*models.Project)) *ProjectRepository_UpsertSplit_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 string
		if args[1] != nil {
			arg1 = args[1].(string)
		}
		var arg2 []*models.Project
		if args[2] != nil {
			arg2 = args[2].([]*models.Project)
		}
		run(
			arg0,
			arg1,
			arg2,
		)
	})
	return _c
}

func (_c *ProjectRepository_UpsertSplit_Call) Return(projects1 []*models.Project, projects2 []*models.Project, err error) *ProjectRepository_UpsertSplit_Call {
	_c.Call.Return(projects1, projects2, err)
	return _c
}

func (_c *ProjectRepository_UpsertSplit_Call) RunAndReturn(run func(tx core.DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error)) *ProjectRepository_UpsertSplit_Call {
	_c.Call.Return(run)
	return _c
}
