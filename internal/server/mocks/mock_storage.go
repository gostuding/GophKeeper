// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/gostuding/GophKeeper/internal/server (interfaces: Storage)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// AddCard mocks base method.
func (m *MockStorage) AddCard(arg0 context.Context, arg1 uint, arg2, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCard", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCard indicates an expected call of AddCard.
func (mr *MockStorageMockRecorder) AddCard(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCard", reflect.TypeOf((*MockStorage)(nil).AddCard), arg0, arg1, arg2, arg3)
}

// AddDataInfo mocks base method.
func (m *MockStorage) AddDataInfo(arg0 context.Context, arg1 uint, arg2, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddDataInfo", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddDataInfo indicates an expected call of AddDataInfo.
func (mr *MockStorageMockRecorder) AddDataInfo(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddDataInfo", reflect.TypeOf((*MockStorage)(nil).AddDataInfo), arg0, arg1, arg2, arg3)
}

// AddFile mocks base method.
func (m *MockStorage) AddFile(arg0 context.Context, arg1 uint, arg2 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddFile", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddFile indicates an expected call of AddFile.
func (mr *MockStorageMockRecorder) AddFile(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddFile", reflect.TypeOf((*MockStorage)(nil).AddFile), arg0, arg1, arg2)
}

// AddFileData mocks base method.
func (m *MockStorage) AddFileData(arg0 context.Context, arg1, arg2 uint, arg3, arg4, arg5 int, arg6 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddFileData", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddFileData indicates an expected call of AddFileData.
func (mr *MockStorageMockRecorder) AddFileData(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddFileData", reflect.TypeOf((*MockStorage)(nil).AddFileData), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// AddFileFinish mocks base method.
func (m *MockStorage) AddFileFinish(arg0 context.Context, arg1 uint, arg2 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddFileFinish", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddFileFinish indicates an expected call of AddFileFinish.
func (mr *MockStorageMockRecorder) AddFileFinish(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddFileFinish", reflect.TypeOf((*MockStorage)(nil).AddFileFinish), arg0, arg1, arg2)
}

// Close mocks base method.
func (m *MockStorage) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockStorageMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockStorage)(nil).Close))
}

// DeleteCard mocks base method.
func (m *MockStorage) DeleteCard(arg0 context.Context, arg1, arg2 uint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteCard", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteCard indicates an expected call of DeleteCard.
func (mr *MockStorageMockRecorder) DeleteCard(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteCard", reflect.TypeOf((*MockStorage)(nil).DeleteCard), arg0, arg1, arg2)
}

// DeleteDataInfo mocks base method.
func (m *MockStorage) DeleteDataInfo(arg0 context.Context, arg1, arg2 uint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteDataInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteDataInfo indicates an expected call of DeleteDataInfo.
func (mr *MockStorageMockRecorder) DeleteDataInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteDataInfo", reflect.TypeOf((*MockStorage)(nil).DeleteDataInfo), arg0, arg1, arg2)
}

// DeleteFile mocks base method.
func (m *MockStorage) DeleteFile(arg0 context.Context, arg1, arg2 uint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteFile", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteFile indicates an expected call of DeleteFile.
func (mr *MockStorageMockRecorder) DeleteFile(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteFile", reflect.TypeOf((*MockStorage)(nil).DeleteFile), arg0, arg1, arg2)
}

// GetCard mocks base method.
func (m *MockStorage) GetCard(arg0 context.Context, arg1, arg2 uint) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCard", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCard indicates an expected call of GetCard.
func (mr *MockStorageMockRecorder) GetCard(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCard", reflect.TypeOf((*MockStorage)(nil).GetCard), arg0, arg1, arg2)
}

// GetCardsList mocks base method.
func (m *MockStorage) GetCardsList(arg0 context.Context, arg1 uint) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCardsList", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCardsList indicates an expected call of GetCardsList.
func (mr *MockStorageMockRecorder) GetCardsList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCardsList", reflect.TypeOf((*MockStorage)(nil).GetCardsList), arg0, arg1)
}

// GetDataInfo mocks base method.
func (m *MockStorage) GetDataInfo(arg0 context.Context, arg1, arg2 uint) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDataInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDataInfo indicates an expected call of GetDataInfo.
func (mr *MockStorageMockRecorder) GetDataInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDataInfo", reflect.TypeOf((*MockStorage)(nil).GetDataInfo), arg0, arg1, arg2)
}

// GetDataInfoList mocks base method.
func (m *MockStorage) GetDataInfoList(arg0 context.Context, arg1 uint) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDataInfoList", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDataInfoList indicates an expected call of GetDataInfoList.
func (mr *MockStorageMockRecorder) GetDataInfoList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDataInfoList", reflect.TypeOf((*MockStorage)(nil).GetDataInfoList), arg0, arg1)
}

// GetFileData mocks base method.
func (m *MockStorage) GetFileData(arg0, arg1, arg2 int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFileData", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFileData indicates an expected call of GetFileData.
func (mr *MockStorageMockRecorder) GetFileData(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFileData", reflect.TypeOf((*MockStorage)(nil).GetFileData), arg0, arg1, arg2)
}

// GetFilesList mocks base method.
func (m *MockStorage) GetFilesList(arg0 context.Context, arg1 uint) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilesList", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFilesList indicates an expected call of GetFilesList.
func (mr *MockStorageMockRecorder) GetFilesList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilesList", reflect.TypeOf((*MockStorage)(nil).GetFilesList), arg0, arg1)
}

// GetPreloadFileInfo mocks base method.
func (m *MockStorage) GetPreloadFileInfo(arg0 context.Context, arg1 uint, arg2 int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPreloadFileInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPreloadFileInfo indicates an expected call of GetPreloadFileInfo.
func (mr *MockStorageMockRecorder) GetPreloadFileInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPreloadFileInfo", reflect.TypeOf((*MockStorage)(nil).GetPreloadFileInfo), arg0, arg1, arg2)
}

// IsUniqueViolation mocks base method.
func (m *MockStorage) IsUniqueViolation(arg0 error) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsUniqueViolation", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsUniqueViolation indicates an expected call of IsUniqueViolation.
func (mr *MockStorageMockRecorder) IsUniqueViolation(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsUniqueViolation", reflect.TypeOf((*MockStorage)(nil).IsUniqueViolation), arg0)
}

// Login mocks base method.
func (m *MockStorage) Login(arg0 context.Context, arg1, arg2 string) (string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Login indicates an expected call of Login.
func (mr *MockStorageMockRecorder) Login(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockStorage)(nil).Login), arg0, arg1, arg2)
}

// Registration mocks base method.
func (m *MockStorage) Registration(arg0 context.Context, arg1, arg2 string) (string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Registration", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Registration indicates an expected call of Registration.
func (mr *MockStorageMockRecorder) Registration(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Registration", reflect.TypeOf((*MockStorage)(nil).Registration), arg0, arg1, arg2)
}

// UpdateCard mocks base method.
func (m *MockStorage) UpdateCard(arg0 context.Context, arg1, arg2 uint, arg3, arg4 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateCard", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateCard indicates an expected call of UpdateCard.
func (mr *MockStorageMockRecorder) UpdateCard(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateCard", reflect.TypeOf((*MockStorage)(nil).UpdateCard), arg0, arg1, arg2, arg3, arg4)
}

// UpdateDataInfo mocks base method.
func (m *MockStorage) UpdateDataInfo(arg0 context.Context, arg1, arg2 uint, arg3, arg4 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateDataInfo", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateDataInfo indicates an expected call of UpdateDataInfo.
func (mr *MockStorageMockRecorder) UpdateDataInfo(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateDataInfo", reflect.TypeOf((*MockStorage)(nil).UpdateDataInfo), arg0, arg1, arg2, arg3, arg4)
}
