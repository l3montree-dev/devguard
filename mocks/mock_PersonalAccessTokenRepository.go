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

// NewPersonalAccessTokenRepository creates a new instance of PersonalAccessTokenRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPersonalAccessTokenRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *PersonalAccessTokenRepository {
	mock := &PersonalAccessTokenRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// PersonalAccessTokenRepository is an autogenerated mock type for the PersonalAccessTokenRepository type
type PersonalAccessTokenRepository struct {
	mock.Mock
}

type PersonalAccessTokenRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *PersonalAccessTokenRepository) EXPECT() *PersonalAccessTokenRepository_Expecter {
	return &PersonalAccessTokenRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Activate(tx core.DB, id uuid.UUID) error {
	ret := _mock.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID) error); ok {
		r0 = returnFunc(tx, id)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type PersonalAccessTokenRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx core.DB
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Activate(tx interface{}, id interface{}) *PersonalAccessTokenRepository_Activate_Call {
	return &PersonalAccessTokenRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *PersonalAccessTokenRepository_Activate_Call) Run(run func(tx core.DB, id uuid.UUID)) *PersonalAccessTokenRepository_Activate_Call {
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

func (_c *PersonalAccessTokenRepository_Activate_Call) Return(err error) *PersonalAccessTokenRepository_Activate_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Activate_Call) RunAndReturn(run func(tx core.DB, id uuid.UUID) error) *PersonalAccessTokenRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// All provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) All() ([]models.PAT, error) {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for All")
	}

	var r0 []models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func() ([]models.PAT, error)); ok {
		return returnFunc()
	}
	if returnFunc, ok := ret.Get(0).(func() []models.PAT); ok {
		r0 = returnFunc()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}
	if returnFunc, ok := ret.Get(1).(func() error); ok {
		r1 = returnFunc()
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_All_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'All'
type PersonalAccessTokenRepository_All_Call struct {
	*mock.Call
}

// All is a helper method to define mock.On call
func (_e *PersonalAccessTokenRepository_Expecter) All() *PersonalAccessTokenRepository_All_Call {
	return &PersonalAccessTokenRepository_All_Call{Call: _e.mock.On("All")}
}

func (_c *PersonalAccessTokenRepository_All_Call) Run(run func()) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_All_Call) Return(pATs []models.PAT, err error) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Return(pATs, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_All_Call) RunAndReturn(run func() ([]models.PAT, error)) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Begin() core.DB {
	ret := _mock.Called()

	if len(ret) == 0 {
		panic("no return value specified for Begin")
	}

	var r0 core.DB
	if returnFunc, ok := ret.Get(0).(func() core.DB); ok {
		r0 = returnFunc()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(core.DB)
		}
	}
	return r0
}

// PersonalAccessTokenRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type PersonalAccessTokenRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *PersonalAccessTokenRepository_Expecter) Begin() *PersonalAccessTokenRepository_Begin_Call {
	return &PersonalAccessTokenRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *PersonalAccessTokenRepository_Begin_Call) Run(run func()) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Begin_Call) Return(v core.DB) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Return(v)
	return _c
}

func (_c *PersonalAccessTokenRepository_Begin_Call) RunAndReturn(run func() core.DB) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Create(tx core.DB, t *models.PAT) error {
	ret := _mock.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, *models.PAT) error); ok {
		r0 = returnFunc(tx, t)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type PersonalAccessTokenRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx core.DB
//   - t *models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) Create(tx interface{}, t interface{}) *PersonalAccessTokenRepository_Create_Call {
	return &PersonalAccessTokenRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *PersonalAccessTokenRepository_Create_Call) Run(run func(tx core.DB, t *models.PAT)) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 *models.PAT
		if args[1] != nil {
			arg1 = args[1].(*models.PAT)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Create_Call) Return(err error) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Create_Call) RunAndReturn(run func(tx core.DB, t *models.PAT) error) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) CreateBatch(tx core.DB, ts []models.PAT) error {
	ret := _mock.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, []models.PAT) error); ok {
		r0 = returnFunc(tx, ts)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type PersonalAccessTokenRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx core.DB
//   - ts []models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *PersonalAccessTokenRepository_CreateBatch_Call {
	return &PersonalAccessTokenRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) Run(run func(tx core.DB, ts []models.PAT)) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 []models.PAT
		if args[1] != nil {
			arg1 = args[1].([]models.PAT)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) Return(err error) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) RunAndReturn(run func(tx core.DB, ts []models.PAT) error) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Delete(tx core.DB, id uuid.UUID) error {
	ret := _mock.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, uuid.UUID) error); ok {
		r0 = returnFunc(tx, id)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type PersonalAccessTokenRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx core.DB
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Delete(tx interface{}, id interface{}) *PersonalAccessTokenRepository_Delete_Call {
	return &PersonalAccessTokenRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *PersonalAccessTokenRepository_Delete_Call) Run(run func(tx core.DB, id uuid.UUID)) *PersonalAccessTokenRepository_Delete_Call {
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

func (_c *PersonalAccessTokenRepository_Delete_Call) Return(err error) *PersonalAccessTokenRepository_Delete_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Delete_Call) RunAndReturn(run func(tx core.DB, id uuid.UUID) error) *PersonalAccessTokenRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteBatch provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) DeleteBatch(tx core.DB, ids []models.PAT) error {
	ret := _mock.Called(tx, ids)

	if len(ret) == 0 {
		panic("no return value specified for DeleteBatch")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, []models.PAT) error); ok {
		r0 = returnFunc(tx, ids)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_DeleteBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteBatch'
type PersonalAccessTokenRepository_DeleteBatch_Call struct {
	*mock.Call
}

// DeleteBatch is a helper method to define mock.On call
//   - tx core.DB
//   - ids []models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) DeleteBatch(tx interface{}, ids interface{}) *PersonalAccessTokenRepository_DeleteBatch_Call {
	return &PersonalAccessTokenRepository_DeleteBatch_Call{Call: _e.mock.On("DeleteBatch", tx, ids)}
}

func (_c *PersonalAccessTokenRepository_DeleteBatch_Call) Run(run func(tx core.DB, ids []models.PAT)) *PersonalAccessTokenRepository_DeleteBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 []models.PAT
		if args[1] != nil {
			arg1 = args[1].([]models.PAT)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteBatch_Call) Return(err error) *PersonalAccessTokenRepository_DeleteBatch_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteBatch_Call) RunAndReturn(run func(tx core.DB, ids []models.PAT) error) *PersonalAccessTokenRepository_DeleteBatch_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteByFingerprint provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) DeleteByFingerprint(fingerprint string) error {
	ret := _mock.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for DeleteByFingerprint")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(string) error); ok {
		r0 = returnFunc(fingerprint)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_DeleteByFingerprint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteByFingerprint'
type PersonalAccessTokenRepository_DeleteByFingerprint_Call struct {
	*mock.Call
}

// DeleteByFingerprint is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) DeleteByFingerprint(fingerprint interface{}) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	return &PersonalAccessTokenRepository_DeleteByFingerprint_Call{Call: _e.mock.On("DeleteByFingerprint", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) Return(err error) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) RunAndReturn(run func(fingerprint string) error) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Return(run)
	return _c
}

// FindByUserIDs provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error) {
	ret := _mock.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for FindByUserIDs")
	}

	var r0 []models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID) ([]models.PAT, error)); ok {
		return returnFunc(userID)
	}
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID) []models.PAT); ok {
		r0 = returnFunc(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}
	if returnFunc, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = returnFunc(userID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_FindByUserIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByUserIDs'
type PersonalAccessTokenRepository_FindByUserIDs_Call struct {
	*mock.Call
}

// FindByUserIDs is a helper method to define mock.On call
//   - userID []uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) FindByUserIDs(userID interface{}) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	return &PersonalAccessTokenRepository_FindByUserIDs_Call{Call: _e.mock.On("FindByUserIDs", userID)}
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) Run(run func(userID []uuid.UUID)) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 []uuid.UUID
		if args[0] != nil {
			arg0 = args[0].([]uuid.UUID)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) Return(pATs []models.PAT, err error) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Return(pATs, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) RunAndReturn(run func(userID []uuid.UUID) ([]models.PAT, error)) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Return(run)
	return _c
}

// GetByFingerprint provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) GetByFingerprint(fingerprint string) (models.PAT, error) {
	ret := _mock.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for GetByFingerprint")
	}

	var r0 models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string) (models.PAT, error)); ok {
		return returnFunc(fingerprint)
	}
	if returnFunc, ok := ret.Get(0).(func(string) models.PAT); ok {
		r0 = returnFunc(fingerprint)
	} else {
		r0 = ret.Get(0).(models.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(string) error); ok {
		r1 = returnFunc(fingerprint)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_GetByFingerprint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByFingerprint'
type PersonalAccessTokenRepository_GetByFingerprint_Call struct {
	*mock.Call
}

// GetByFingerprint is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) GetByFingerprint(fingerprint interface{}) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	return &PersonalAccessTokenRepository_GetByFingerprint_Call{Call: _e.mock.On("GetByFingerprint", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) Return(pAT models.PAT, err error) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Return(pAT, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) RunAndReturn(run func(fingerprint string) (models.PAT, error)) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) GetDB(tx core.DB) core.DB {
	ret := _mock.Called(tx)

	if len(ret) == 0 {
		panic("no return value specified for GetDB")
	}

	var r0 core.DB
	if returnFunc, ok := ret.Get(0).(func(core.DB) core.DB); ok {
		r0 = returnFunc(tx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(core.DB)
		}
	}
	return r0
}

// PersonalAccessTokenRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type PersonalAccessTokenRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx core.DB
func (_e *PersonalAccessTokenRepository_Expecter) GetDB(tx interface{}) *PersonalAccessTokenRepository_GetDB_Call {
	return &PersonalAccessTokenRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) Run(run func(tx core.DB)) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) Return(v core.DB) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Return(v)
	return _c
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) RunAndReturn(run func(tx core.DB) core.DB) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) List(ids []uuid.UUID) ([]models.PAT, error) {
	ret := _mock.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID) ([]models.PAT, error)); ok {
		return returnFunc(ids)
	}
	if returnFunc, ok := ret.Get(0).(func([]uuid.UUID) []models.PAT); ok {
		r0 = returnFunc(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}
	if returnFunc, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = returnFunc(ids)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type PersonalAccessTokenRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) List(ids interface{}) *PersonalAccessTokenRepository_List_Call {
	return &PersonalAccessTokenRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *PersonalAccessTokenRepository_List_Call) Run(run func(ids []uuid.UUID)) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 []uuid.UUID
		if args[0] != nil {
			arg0 = args[0].([]uuid.UUID)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_List_Call) Return(pATs []models.PAT, err error) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Return(pATs, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_List_Call) RunAndReturn(run func(ids []uuid.UUID) ([]models.PAT, error)) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// ListByUserID provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) ListByUserID(userID string) ([]models.PAT, error) {
	ret := _mock.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for ListByUserID")
	}

	var r0 []models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(string) ([]models.PAT, error)); ok {
		return returnFunc(userID)
	}
	if returnFunc, ok := ret.Get(0).(func(string) []models.PAT); ok {
		r0 = returnFunc(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(string) error); ok {
		r1 = returnFunc(userID)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_ListByUserID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListByUserID'
type PersonalAccessTokenRepository_ListByUserID_Call struct {
	*mock.Call
}

// ListByUserID is a helper method to define mock.On call
//   - userID string
func (_e *PersonalAccessTokenRepository_Expecter) ListByUserID(userID interface{}) *PersonalAccessTokenRepository_ListByUserID_Call {
	return &PersonalAccessTokenRepository_ListByUserID_Call{Call: _e.mock.On("ListByUserID", userID)}
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) Run(run func(userID string)) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) Return(pATs []models.PAT, err error) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Return(pATs, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) RunAndReturn(run func(userID string) ([]models.PAT, error)) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Return(run)
	return _c
}

// MarkAsLastUsedNow provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) MarkAsLastUsedNow(fingerprint string) error {
	ret := _mock.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for MarkAsLastUsedNow")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(string) error); ok {
		r0 = returnFunc(fingerprint)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_MarkAsLastUsedNow_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MarkAsLastUsedNow'
type PersonalAccessTokenRepository_MarkAsLastUsedNow_Call struct {
	*mock.Call
}

// MarkAsLastUsedNow is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) MarkAsLastUsedNow(fingerprint interface{}) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	return &PersonalAccessTokenRepository_MarkAsLastUsedNow_Call{Call: _e.mock.On("MarkAsLastUsedNow", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 string
		if args[0] != nil {
			arg0 = args[0].(string)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) Return(err error) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) RunAndReturn(run func(fingerprint string) error) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Read(id uuid.UUID) (models.PAT, error) {
	ret := _mock.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.PAT
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) (models.PAT, error)); ok {
		return returnFunc(id)
	}
	if returnFunc, ok := ret.Get(0).(func(uuid.UUID) models.PAT); ok {
		r0 = returnFunc(id)
	} else {
		r0 = ret.Get(0).(models.PAT)
	}
	if returnFunc, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = returnFunc(id)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// PersonalAccessTokenRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type PersonalAccessTokenRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Read(id interface{}) *PersonalAccessTokenRepository_Read_Call {
	return &PersonalAccessTokenRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *PersonalAccessTokenRepository_Read_Call) Run(run func(id uuid.UUID)) *PersonalAccessTokenRepository_Read_Call {
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

func (_c *PersonalAccessTokenRepository_Read_Call) Return(pAT models.PAT, err error) *PersonalAccessTokenRepository_Read_Call {
	_c.Call.Return(pAT, err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Read_Call) RunAndReturn(run func(id uuid.UUID) (models.PAT, error)) *PersonalAccessTokenRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Save(tx core.DB, t *models.PAT) error {
	ret := _mock.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, *models.PAT) error); ok {
		r0 = returnFunc(tx, t)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type PersonalAccessTokenRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx core.DB
//   - t *models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) Save(tx interface{}, t interface{}) *PersonalAccessTokenRepository_Save_Call {
	return &PersonalAccessTokenRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *PersonalAccessTokenRepository_Save_Call) Run(run func(tx core.DB, t *models.PAT)) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 *models.PAT
		if args[1] != nil {
			arg1 = args[1].(*models.PAT)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Save_Call) Return(err error) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Save_Call) RunAndReturn(run func(tx core.DB, t *models.PAT) error) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) SaveBatch(tx core.DB, ts []models.PAT) error {
	ret := _mock.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(core.DB, []models.PAT) error); ok {
		r0 = returnFunc(tx, ts)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type PersonalAccessTokenRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx core.DB
//   - ts []models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *PersonalAccessTokenRepository_SaveBatch_Call {
	return &PersonalAccessTokenRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) Run(run func(tx core.DB, ts []models.PAT)) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 core.DB
		if args[0] != nil {
			arg0 = args[0].(core.DB)
		}
		var arg1 []models.PAT
		if args[1] != nil {
			arg1 = args[1].([]models.PAT)
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) Return(err error) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) RunAndReturn(run func(tx core.DB, ts []models.PAT) error) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Transaction(fn func(tx core.DB) error) error {
	ret := _mock.Called(fn)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(func(tx core.DB) error) error); ok {
		r0 = returnFunc(fn)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type PersonalAccessTokenRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - fn func(tx core.DB) error
func (_e *PersonalAccessTokenRepository_Expecter) Transaction(fn interface{}) *PersonalAccessTokenRepository_Transaction_Call {
	return &PersonalAccessTokenRepository_Transaction_Call{Call: _e.mock.On("Transaction", fn)}
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) Run(run func(fn func(tx core.DB) error)) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 func(tx core.DB) error
		if args[0] != nil {
			arg0 = args[0].(func(tx core.DB) error)
		}
		run(
			arg0,
		)
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) Return(err error) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) RunAndReturn(run func(fn func(tx core.DB) error) error) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// Upsert provides a mock function for the type PersonalAccessTokenRepository
func (_mock *PersonalAccessTokenRepository) Upsert(t *[]*models.PAT, conflictingColumns []clause.Column, updateOnly []string) error {
	ret := _mock.Called(t, conflictingColumns, updateOnly)

	if len(ret) == 0 {
		panic("no return value specified for Upsert")
	}

	var r0 error
	if returnFunc, ok := ret.Get(0).(func(*[]*models.PAT, []clause.Column, []string) error); ok {
		r0 = returnFunc(t, conflictingColumns, updateOnly)
	} else {
		r0 = ret.Error(0)
	}
	return r0
}

// PersonalAccessTokenRepository_Upsert_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Upsert'
type PersonalAccessTokenRepository_Upsert_Call struct {
	*mock.Call
}

// Upsert is a helper method to define mock.On call
//   - t *[]*models.PAT
//   - conflictingColumns []clause.Column
//   - updateOnly []string
func (_e *PersonalAccessTokenRepository_Expecter) Upsert(t interface{}, conflictingColumns interface{}, updateOnly interface{}) *PersonalAccessTokenRepository_Upsert_Call {
	return &PersonalAccessTokenRepository_Upsert_Call{Call: _e.mock.On("Upsert", t, conflictingColumns, updateOnly)}
}

func (_c *PersonalAccessTokenRepository_Upsert_Call) Run(run func(t *[]*models.PAT, conflictingColumns []clause.Column, updateOnly []string)) *PersonalAccessTokenRepository_Upsert_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 *[]*models.PAT
		if args[0] != nil {
			arg0 = args[0].(*[]*models.PAT)
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

func (_c *PersonalAccessTokenRepository_Upsert_Call) Return(err error) *PersonalAccessTokenRepository_Upsert_Call {
	_c.Call.Return(err)
	return _c
}

func (_c *PersonalAccessTokenRepository_Upsert_Call) RunAndReturn(run func(t *[]*models.PAT, conflictingColumns []clause.Column, updateOnly []string) error) *PersonalAccessTokenRepository_Upsert_Call {
	_c.Call.Return(run)
	return _c
}
