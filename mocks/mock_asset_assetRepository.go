// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// AssetAssetRepository is an autogenerated mock type for the assetRepository type
type AssetAssetRepository struct {
	mock.Mock
}

type AssetAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetAssetRepository) EXPECT() *AssetAssetRepository_Expecter {
	return &AssetAssetRepository_Expecter{mock: &_m.Mock}
}

// Save provides a mock function with given fields: tx, _a1
func (_m *AssetAssetRepository) Save(tx core.DB, _a1 *models.Asset) error {
	ret := _m.Called(tx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(core.DB, *models.Asset) error); ok {
		r0 = rf(tx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetAssetRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type AssetAssetRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx core.DB
//   - _a1 *models.Asset
func (_e *AssetAssetRepository_Expecter) Save(tx interface{}, _a1 interface{}) *AssetAssetRepository_Save_Call {
	return &AssetAssetRepository_Save_Call{Call: _e.mock.On("Save", tx, _a1)}
}

func (_c *AssetAssetRepository_Save_Call) Run(run func(tx core.DB, _a1 *models.Asset)) *AssetAssetRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].(*models.Asset))
	})
	return _c
}

func (_c *AssetAssetRepository_Save_Call) Return(_a0 error) *AssetAssetRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetAssetRepository_Save_Call) RunAndReturn(run func(core.DB, *models.Asset) error) *AssetAssetRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: txFunc
func (_m *AssetAssetRepository) Transaction(txFunc func(core.DB) error) error {
	ret := _m.Called(txFunc)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(core.DB) error) error); ok {
		r0 = rf(txFunc)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetAssetRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type AssetAssetRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - txFunc func(core.DB) error
func (_e *AssetAssetRepository_Expecter) Transaction(txFunc interface{}) *AssetAssetRepository_Transaction_Call {
	return &AssetAssetRepository_Transaction_Call{Call: _e.mock.On("Transaction", txFunc)}
}

func (_c *AssetAssetRepository_Transaction_Call) Run(run func(txFunc func(core.DB) error)) *AssetAssetRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(core.DB) error))
	})
	return _c
}

func (_c *AssetAssetRepository_Transaction_Call) Return(_a0 error) *AssetAssetRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetAssetRepository_Transaction_Call) RunAndReturn(run func(func(core.DB) error) error) *AssetAssetRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetAssetRepository creates a new instance of AssetAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetAssetRepository {
	mock := &AssetAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
