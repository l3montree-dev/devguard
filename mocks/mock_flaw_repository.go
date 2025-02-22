// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"

	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// FlawRepository is an autogenerated mock type for the repository type
type FlawRepository struct {
	mock.Mock
}

type FlawRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *FlawRepository) EXPECT() *FlawRepository_Expecter {
	return &FlawRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *FlawRepository) Activate(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type FlawRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *FlawRepository_Expecter) Activate(tx interface{}, id interface{}) *FlawRepository_Activate_Call {
	return &FlawRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *FlawRepository_Activate_Call) Run(run func(tx *gorm.DB, id string)) *FlawRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *FlawRepository_Activate_Call) Return(_a0 error) *FlawRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, string) error) *FlawRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *FlawRepository) Begin() *gorm.DB {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Begin")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func() *gorm.DB); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// FlawRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type FlawRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *FlawRepository_Expecter) Begin() *FlawRepository_Begin_Call {
	return &FlawRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *FlawRepository_Begin_Call) Run(run func()) *FlawRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *FlawRepository_Begin_Call) Return(_a0 *gorm.DB) *FlawRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *FlawRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *FlawRepository) Create(tx *gorm.DB, t *models.Flaw) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Flaw) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type FlawRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.Flaw
func (_e *FlawRepository_Expecter) Create(tx interface{}, t interface{}) *FlawRepository_Create_Call {
	return &FlawRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *FlawRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.Flaw)) *FlawRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Flaw))
	})
	return _c
}

func (_c *FlawRepository_Create_Call) Return(_a0 error) *FlawRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.Flaw) error) *FlawRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *FlawRepository) CreateBatch(tx *gorm.DB, ts []models.Flaw) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Flaw) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type FlawRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.Flaw
func (_e *FlawRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *FlawRepository_CreateBatch_Call {
	return &FlawRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *FlawRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.Flaw)) *FlawRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Flaw))
	})
	return _c
}

func (_c *FlawRepository_CreateBatch_Call) Return(_a0 error) *FlawRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Flaw) error) *FlawRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *FlawRepository) Delete(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type FlawRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *FlawRepository_Expecter) Delete(tx interface{}, id interface{}) *FlawRepository_Delete_Call {
	return &FlawRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *FlawRepository_Delete_Call) Run(run func(tx *gorm.DB, id string)) *FlawRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *FlawRepository_Delete_Call) Return(_a0 error) *FlawRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, string) error) *FlawRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetByAssetId provides a mock function with given fields: tx, assetId
func (_m *FlawRepository) GetByAssetId(tx *gorm.DB, assetId uuid.UUID) ([]models.Flaw, error) {
	ret := _m.Called(tx, assetId)

	if len(ret) == 0 {
		panic("no return value specified for GetByAssetId")
	}

	var r0 []models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)); ok {
		return rf(tx, assetId)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.Flaw); ok {
		r0 = rf(tx, assetId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Flaw)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_GetByAssetId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByAssetId'
type FlawRepository_GetByAssetId_Call struct {
	*mock.Call
}

// GetByAssetId is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetId uuid.UUID
func (_e *FlawRepository_Expecter) GetByAssetId(tx interface{}, assetId interface{}) *FlawRepository_GetByAssetId_Call {
	return &FlawRepository_GetByAssetId_Call{Call: _e.mock.On("GetByAssetId", tx, assetId)}
}

func (_c *FlawRepository_GetByAssetId_Call) Run(run func(tx *gorm.DB, assetId uuid.UUID)) *FlawRepository_GetByAssetId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *FlawRepository_GetByAssetId_Call) Return(_a0 []models.Flaw, _a1 error) *FlawRepository_GetByAssetId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_GetByAssetId_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)) *FlawRepository_GetByAssetId_Call {
	_c.Call.Return(run)
	return _c
}

// GetByAssetIdPaged provides a mock function with given fields: tx, pageInfo, search, filter, sort, assetId
func (_m *FlawRepository) GetByAssetIdPaged(tx *gorm.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], map[string]int, error) {
	ret := _m.Called(tx, pageInfo, search, filter, sort, assetId)

	if len(ret) == 0 {
		panic("no return value specified for GetByAssetIdPaged")
	}

	var r0 core.Paged[models.Flaw]
	var r1 map[string]int
	var r2 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) (core.Paged[models.Flaw], map[string]int, error)); ok {
		return rf(tx, pageInfo, search, filter, sort, assetId)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) core.Paged[models.Flaw]); ok {
		r0 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		r0 = ret.Get(0).(core.Paged[models.Flaw])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) map[string]int); ok {
		r1 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(map[string]int)
		}
	}

	if rf, ok := ret.Get(2).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) error); ok {
		r2 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// FlawRepository_GetByAssetIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByAssetIdPaged'
type FlawRepository_GetByAssetIdPaged_Call struct {
	*mock.Call
}

// GetByAssetIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
//   - assetId uuid.UUID
func (_e *FlawRepository_Expecter) GetByAssetIdPaged(tx interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}, assetId interface{}) *FlawRepository_GetByAssetIdPaged_Call {
	return &FlawRepository_GetByAssetIdPaged_Call{Call: _e.mock.On("GetByAssetIdPaged", tx, pageInfo, search, filter, sort, assetId)}
}

func (_c *FlawRepository_GetByAssetIdPaged_Call) Run(run func(tx *gorm.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID)) *FlawRepository_GetByAssetIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(core.PageInfo), args[2].(string), args[3].([]core.FilterQuery), args[4].([]core.SortQuery), args[5].(uuid.UUID))
	})
	return _c
}

func (_c *FlawRepository_GetByAssetIdPaged_Call) Return(_a0 core.Paged[models.Flaw], _a1 map[string]int, _a2 error) *FlawRepository_GetByAssetIdPaged_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *FlawRepository_GetByAssetIdPaged_Call) RunAndReturn(run func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) (core.Paged[models.Flaw], map[string]int, error)) *FlawRepository_GetByAssetIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *FlawRepository) GetDB(tx *gorm.DB) *gorm.DB {
	ret := _m.Called(tx)

	if len(ret) == 0 {
		panic("no return value specified for GetDB")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func(*gorm.DB) *gorm.DB); ok {
		r0 = rf(tx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// FlawRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type FlawRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *FlawRepository_Expecter) GetDB(tx interface{}) *FlawRepository_GetDB_Call {
	return &FlawRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *FlawRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *FlawRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *FlawRepository_GetDB_Call) Return(_a0 *gorm.DB) *FlawRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *FlawRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// GetFlawsByAssetIdPagedAndFlat provides a mock function with given fields: tx, assetId, pageInfo, search, filter, sort
func (_m *FlawRepository) GetFlawsByAssetIdPagedAndFlat(tx *gorm.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {
	ret := _m.Called(tx, assetId, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetFlawsByAssetIdPagedAndFlat")
	}

	var r0 core.Paged[models.Flaw]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)); ok {
		return rf(tx, assetId, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.Flaw]); ok {
		r0 = rf(tx, assetId, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.Flaw])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, assetId, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFlawsByAssetIdPagedAndFlat'
type FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call struct {
	*mock.Call
}

// GetFlawsByAssetIdPagedAndFlat is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetId uuid.UUID
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *FlawRepository_Expecter) GetFlawsByAssetIdPagedAndFlat(tx interface{}, assetId interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call {
	return &FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call{Call: _e.mock.On("GetFlawsByAssetIdPagedAndFlat", tx, assetId, pageInfo, search, filter, sort)}
}

func (_c *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call) Run(run func(tx *gorm.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call) Return(_a0 core.Paged[models.Flaw], _a1 error) *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)) *FlawRepository_GetFlawsByAssetIdPagedAndFlat_Call {
	_c.Call.Return(run)
	return _c
}

// GetFlawsByOrgIdPaged provides a mock function with given fields: tx, userAllowedProjectIds, pageInfo, search, filter, sort
func (_m *FlawRepository) GetFlawsByOrgIdPaged(tx *gorm.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {
	ret := _m.Called(tx, userAllowedProjectIds, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetFlawsByOrgIdPaged")
	}

	var r0 core.Paged[models.Flaw]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)); ok {
		return rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.Flaw]); ok {
		r0 = rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.Flaw])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_GetFlawsByOrgIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFlawsByOrgIdPaged'
type FlawRepository_GetFlawsByOrgIdPaged_Call struct {
	*mock.Call
}

// GetFlawsByOrgIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userAllowedProjectIds []string
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *FlawRepository_Expecter) GetFlawsByOrgIdPaged(tx interface{}, userAllowedProjectIds interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *FlawRepository_GetFlawsByOrgIdPaged_Call {
	return &FlawRepository_GetFlawsByOrgIdPaged_Call{Call: _e.mock.On("GetFlawsByOrgIdPaged", tx, userAllowedProjectIds, pageInfo, search, filter, sort)}
}

func (_c *FlawRepository_GetFlawsByOrgIdPaged_Call) Run(run func(tx *gorm.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *FlawRepository_GetFlawsByOrgIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]string), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *FlawRepository_GetFlawsByOrgIdPaged_Call) Return(_a0 core.Paged[models.Flaw], _a1 error) *FlawRepository_GetFlawsByOrgIdPaged_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_GetFlawsByOrgIdPaged_Call) RunAndReturn(run func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)) *FlawRepository_GetFlawsByOrgIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// GetFlawsByProjectIdPaged provides a mock function with given fields: tx, projectID, pageInfo, search, filter, sort
func (_m *FlawRepository) GetFlawsByProjectIdPaged(tx *gorm.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {
	ret := _m.Called(tx, projectID, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetFlawsByProjectIdPaged")
	}

	var r0 core.Paged[models.Flaw]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)); ok {
		return rf(tx, projectID, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.Flaw]); ok {
		r0 = rf(tx, projectID, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.Flaw])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, projectID, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_GetFlawsByProjectIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFlawsByProjectIdPaged'
type FlawRepository_GetFlawsByProjectIdPaged_Call struct {
	*mock.Call
}

// GetFlawsByProjectIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - projectID uuid.UUID
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *FlawRepository_Expecter) GetFlawsByProjectIdPaged(tx interface{}, projectID interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *FlawRepository_GetFlawsByProjectIdPaged_Call {
	return &FlawRepository_GetFlawsByProjectIdPaged_Call{Call: _e.mock.On("GetFlawsByProjectIdPaged", tx, projectID, pageInfo, search, filter, sort)}
}

func (_c *FlawRepository_GetFlawsByProjectIdPaged_Call) Run(run func(tx *gorm.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *FlawRepository_GetFlawsByProjectIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *FlawRepository_GetFlawsByProjectIdPaged_Call) Return(_a0 core.Paged[models.Flaw], _a1 error) *FlawRepository_GetFlawsByProjectIdPaged_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_GetFlawsByProjectIdPaged_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.Flaw], error)) *FlawRepository_GetFlawsByProjectIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *FlawRepository) List(ids []string) ([]models.Flaw, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func([]string) ([]models.Flaw, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]string) []models.Flaw); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Flaw)
		}
	}

	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type FlawRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []string
func (_e *FlawRepository_Expecter) List(ids interface{}) *FlawRepository_List_Call {
	return &FlawRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *FlawRepository_List_Call) Run(run func(ids []string)) *FlawRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]string))
	})
	return _c
}

func (_c *FlawRepository_List_Call) Return(_a0 []models.Flaw, _a1 error) *FlawRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_List_Call) RunAndReturn(run func([]string) ([]models.Flaw, error)) *FlawRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *FlawRepository) Read(id string) (models.Flaw, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.Flaw, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(string) models.Flaw); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.Flaw)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type FlawRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id string
func (_e *FlawRepository_Expecter) Read(id interface{}) *FlawRepository_Read_Call {
	return &FlawRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *FlawRepository_Read_Call) Run(run func(id string)) *FlawRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *FlawRepository_Read_Call) Return(_a0 models.Flaw, _a1 error) *FlawRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawRepository_Read_Call) RunAndReturn(run func(string) (models.Flaw, error)) *FlawRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *FlawRepository) Save(tx *gorm.DB, t *models.Flaw) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Flaw) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type FlawRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.Flaw
func (_e *FlawRepository_Expecter) Save(tx interface{}, t interface{}) *FlawRepository_Save_Call {
	return &FlawRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *FlawRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.Flaw)) *FlawRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Flaw))
	})
	return _c
}

func (_c *FlawRepository_Save_Call) Return(_a0 error) *FlawRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Flaw) error) *FlawRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *FlawRepository) SaveBatch(tx *gorm.DB, ts []models.Flaw) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Flaw) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type FlawRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.Flaw
func (_e *FlawRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *FlawRepository_SaveBatch_Call {
	return &FlawRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *FlawRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.Flaw)) *FlawRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Flaw))
	})
	return _c
}

func (_c *FlawRepository_SaveBatch_Call) Return(_a0 error) *FlawRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Flaw) error) *FlawRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *FlawRepository) Transaction(_a0 func(*gorm.DB) error) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type FlawRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *FlawRepository_Expecter) Transaction(_a0 interface{}) *FlawRepository_Transaction_Call {
	return &FlawRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *FlawRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *FlawRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *FlawRepository_Transaction_Call) Return(_a0 error) *FlawRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *FlawRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewFlawRepository creates a new instance of FlawRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlawRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *FlawRepository {
	mock := &FlawRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
