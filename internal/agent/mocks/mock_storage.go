// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/gostuding/GophKeeper/internal/agent (interfaces: Storage)

// Package mocks is a generated GoMock package.
package mocks

import (
	fs "io/fs"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	storage "github.com/gostuding/GophKeeper/internal/agent/storage"
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
func (m *MockStorage) AddCard(arg0 string, arg1 *storage.CardInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCard", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCard indicates an expected call of AddCard.
func (mr *MockStorageMockRecorder) AddCard(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCard", reflect.TypeOf((*MockStorage)(nil).AddCard), arg0, arg1)
}

// AddDataInfo mocks base method.
func (m *MockStorage) AddDataInfo(arg0, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddDataInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddDataInfo indicates an expected call of AddDataInfo.
func (mr *MockStorageMockRecorder) AddDataInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddDataInfo", reflect.TypeOf((*MockStorage)(nil).AddDataInfo), arg0, arg1, arg2)
}

// AddFile mocks base method.
func (m *MockStorage) AddFile(arg0, arg1 string, arg2 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddFile", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddFile indicates an expected call of AddFile.
func (mr *MockStorageMockRecorder) AddFile(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddFile", reflect.TypeOf((*MockStorage)(nil).AddFile), arg0, arg1, arg2)
}

// Authentification mocks base method.
func (m *MockStorage) Authentification(arg0, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authentification", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Authentification indicates an expected call of Authentification.
func (mr *MockStorageMockRecorder) Authentification(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authentification", reflect.TypeOf((*MockStorage)(nil).Authentification), arg0, arg1, arg2)
}

// Check mocks base method.
func (m *MockStorage) Check(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Check", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Check indicates an expected call of Check.
func (mr *MockStorageMockRecorder) Check(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Check", reflect.TypeOf((*MockStorage)(nil).Check), arg0)
}

// DeleteItem mocks base method.
func (m *MockStorage) DeleteItem(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteItem", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteItem indicates an expected call of DeleteItem.
func (mr *MockStorageMockRecorder) DeleteItem(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteItem", reflect.TypeOf((*MockStorage)(nil).DeleteItem), arg0)
}

// FihishFileTransfer mocks base method.
func (m *MockStorage) FihishFileTransfer(arg0 string, arg1 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FihishFileTransfer", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// FihishFileTransfer indicates an expected call of FihishFileTransfer.
func (mr *MockStorageMockRecorder) FihishFileTransfer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FihishFileTransfer", reflect.TypeOf((*MockStorage)(nil).FihishFileTransfer), arg0, arg1)
}

// GetCard mocks base method.
func (m *MockStorage) GetCard(arg0 string) (*storage.CardInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCard", arg0)
	ret0, _ := ret[0].(*storage.CardInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCard indicates an expected call of GetCard.
func (mr *MockStorageMockRecorder) GetCard(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCard", reflect.TypeOf((*MockStorage)(nil).GetCard), arg0)
}

// GetDataInfo mocks base method.
func (m *MockStorage) GetDataInfo(arg0 string) (*storage.DataInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDataInfo", arg0)
	ret0, _ := ret[0].(*storage.DataInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDataInfo indicates an expected call of GetDataInfo.
func (mr *MockStorageMockRecorder) GetDataInfo(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDataInfo", reflect.TypeOf((*MockStorage)(nil).GetDataInfo), arg0)
}

// GetFile mocks base method.
func (m *MockStorage) GetFile(arg0, arg1 string, arg2 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFile", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// GetFile indicates an expected call of GetFile.
func (mr *MockStorageMockRecorder) GetFile(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFile", reflect.TypeOf((*MockStorage)(nil).GetFile), arg0, arg1, arg2)
}

// GetFilesList mocks base method.
func (m *MockStorage) GetFilesList(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilesList", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFilesList indicates an expected call of GetFilesList.
func (mr *MockStorageMockRecorder) GetFilesList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilesList", reflect.TypeOf((*MockStorage)(nil).GetFilesList), arg0)
}

// GetItemsListCommon mocks base method.
func (m *MockStorage) GetItemsListCommon(arg0, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetItemsListCommon", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetItemsListCommon indicates an expected call of GetItemsListCommon.
func (mr *MockStorageMockRecorder) GetItemsListCommon(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetItemsListCommon", reflect.TypeOf((*MockStorage)(nil).GetItemsListCommon), arg0, arg1)
}

// GetNewFileID mocks base method.
func (m *MockStorage) GetNewFileID(arg0 string, arg1 fs.FileInfo) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNewFileID", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNewFileID indicates an expected call of GetNewFileID.
func (mr *MockStorageMockRecorder) GetNewFileID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNewFileID", reflect.TypeOf((*MockStorage)(nil).GetNewFileID), arg0, arg1)
}

// GetPreloadFileInfo mocks base method.
func (m *MockStorage) GetPreloadFileInfo(arg0 string) (string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPreloadFileInfo", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetPreloadFileInfo indicates an expected call of GetPreloadFileInfo.
func (mr *MockStorageMockRecorder) GetPreloadFileInfo(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPreloadFileInfo", reflect.TypeOf((*MockStorage)(nil).GetPreloadFileInfo), arg0)
}

// ServerAESKey mocks base method.
func (m *MockStorage) ServerAESKey() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ServerAESKey")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// ServerAESKey indicates an expected call of ServerAESKey.
func (mr *MockStorageMockRecorder) ServerAESKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ServerAESKey", reflect.TypeOf((*MockStorage)(nil).ServerAESKey))
}

// SetUserAESKey mocks base method.
func (m *MockStorage) SetUserAESKey(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUserAESKey", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUserAESKey indicates an expected call of SetUserAESKey.
func (mr *MockStorageMockRecorder) SetUserAESKey(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUserAESKey", reflect.TypeOf((*MockStorage)(nil).SetUserAESKey), arg0)
}

// UpdateCard mocks base method.
func (m *MockStorage) UpdateCard(arg0 string, arg1 *storage.CardInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateCard", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateCard indicates an expected call of UpdateCard.
func (mr *MockStorageMockRecorder) UpdateCard(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateCard", reflect.TypeOf((*MockStorage)(nil).UpdateCard), arg0, arg1)
}

// UpdateDataInfo mocks base method.
func (m *MockStorage) UpdateDataInfo(arg0, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateDataInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateDataInfo indicates an expected call of UpdateDataInfo.
func (mr *MockStorageMockRecorder) UpdateDataInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateDataInfo", reflect.TypeOf((*MockStorage)(nil).UpdateDataInfo), arg0, arg1, arg2)
}
