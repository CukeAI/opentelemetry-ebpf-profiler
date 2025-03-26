// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package art // import "go.opentelemetry.io/ebpf-profiler/interpreter/art"

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <stdbool.h>
#include "./dex_file_external.h"

#define ADEXFILE_ERROR_LIB_NOT_LOADED 0xff

typedef ADexFile_MethodCallback *ADexFile_MethodCallbackPtr;

typedef ADexFile_Error (*ADexFile_create_func)(const void* _Nonnull address,
                               size_t size,
                               size_t* _Nullable new_size,
                               const char* _Nonnull location,
                               ADexFile* _Nullable * _Nonnull out_dex_file);

typedef void (*ADexFile_destroy_func)(ADexFile* _Nullable self);

typedef size_t (*ADexFile_findMethodAtOffset_func)(ADexFile* _Nonnull self,
                                   size_t dex_offset,
                                   ADexFile_MethodCallback* _Nonnull callback,
                                   void* _Nullable callback_data);

typedef size_t (*ADexFile_forEachMethod_func)(ADexFile* _Nonnull self,
                              ADexFile_MethodCallback* _Nonnull callback,
                              void* _Nullable callback_data);

typedef size_t (*ADexFile_Method_getCodeOffset_func)(const ADexFile_Method* _Nonnull self,
                                     size_t* _Nullable out_size);

typedef const char* _Nonnull (*ADexFile_Method_getName_func)(const ADexFile_Method* _Nonnull self,
                                             size_t* _Nullable out_size);

typedef const char* _Nonnull (*ADexFile_Method_getQualifiedName_func)(const ADexFile_Method* _Nonnull self,
                                                      int with_params,
                                                      size_t* _Nullable out_size);

typedef const char* _Nonnull (*ADexFile_Method_getClassDescriptor_func)(const ADexFile_Method* _Nonnull self,
                                                        size_t* _Nullable out_size);

typedef const char* _Nullable (*ADexFile_Error_toString_func)(ADexFile_Error self);

struct DexFileApi {
    bool loaded;
	ADexFile_create_func ADexFile_create_ptr;
	ADexFile_destroy_func ADexFile_destroy_ptr;
	ADexFile_findMethodAtOffset_func ADexFile_findMethodAtOffset_ptr;
	ADexFile_forEachMethod_func ADexFile_forEachMethod_ptr;
	ADexFile_Method_getCodeOffset_func ADexFile_Method_getCodeOffset_ptr;
	ADexFile_Method_getName_func ADexFile_Method_getName_ptr;
	ADexFile_Method_getQualifiedName_func ADexFile_Method_getQualifiedName_ptr;
	ADexFile_Method_getClassDescriptor_func ADexFile_Method_getClassDescriptor_ptr;
	ADexFile_Error_toString_func ADexFile_Error_toString_ptr;
} DexFileApiInstance;

ADexFile_Error ADexFile_create(const void* _Nonnull address,
                               size_t size,
                               size_t* _Nullable new_size,
                               const char* _Nonnull location,
                               ADexFile* _Nullable * _Nonnull out_dex_file) {
	if (DexFileApiInstance.ADexFile_create_ptr == NULL) {
		return ADEXFILE_ERROR_LIB_NOT_LOADED;
	}
	return DexFileApiInstance.ADexFile_create_ptr(address, size, new_size, location, out_dex_file);
}

void ADexFile_destroy(ADexFile* _Nullable self) {
	if (DexFileApiInstance.ADexFile_destroy_ptr == NULL) {
		return;
	}
	return DexFileApiInstance.ADexFile_destroy_ptr(self);
}

size_t ADexFile_findMethodAtOffset(ADexFile* _Nonnull self,
                                   size_t dex_offset,
                                   ADexFile_MethodCallback* _Nonnull callback,
                                   void* _Nullable callback_data) {
	if (DexFileApiInstance.ADexFile_findMethodAtOffset_ptr == NULL) {
		return 0;
	}
	return DexFileApiInstance.ADexFile_findMethodAtOffset_ptr(self, dex_offset, callback, callback_data);
}

size_t ADexFile_forEachMethod(ADexFile* _Nonnull self,
                              ADexFile_MethodCallback* _Nonnull callback,
                              void* _Nullable callback_data) {
	if (DexFileApiInstance.ADexFile_forEachMethod_ptr == NULL) {
		return 0;
	}
	return DexFileApiInstance.ADexFile_forEachMethod_ptr(self, callback, callback_data);
}

size_t ADexFile_Method_getCodeOffset(const ADexFile_Method* _Nonnull self,
                                     size_t* _Nullable out_size) {
	if (DexFileApiInstance.ADexFile_Method_getCodeOffset_ptr == NULL) {
		return 0;
	}
	return DexFileApiInstance.ADexFile_Method_getCodeOffset_ptr(self, out_size);
}

const char* _Nonnull ADexFile_Method_getName(const ADexFile_Method* _Nonnull self,
                                             size_t* _Nullable out_size) {
	if (DexFileApiInstance.ADexFile_Method_getName_ptr == NULL) {
		return "";
	}
	return DexFileApiInstance.ADexFile_Method_getName_ptr(self, out_size);
}

const char* _Nonnull ADexFile_Method_getQualifiedName(const ADexFile_Method* _Nonnull self,
                                                      int with_params,
                                                      size_t* _Nullable out_size) {
	if (DexFileApiInstance.ADexFile_Method_getQualifiedName_ptr == NULL) {
		return "";
	}
	return DexFileApiInstance.ADexFile_Method_getQualifiedName_ptr(self, with_params, out_size);
}

const char* _Nonnull ADexFile_Method_getClassDescriptor(const ADexFile_Method* _Nonnull self,
                                                        size_t* _Nullable out_size) {
	if (DexFileApiInstance.ADexFile_Method_getClassDescriptor_ptr == NULL) {
		return "";
	}
	return DexFileApiInstance.ADexFile_Method_getClassDescriptor_ptr(self, out_size);
}

const char* _Nullable ADexFile_Error_toString(ADexFile_Error self) {
	if (DexFileApiInstance.ADexFile_Error_toString_ptr == NULL) {
		return "lib not loaded";
	}
	return DexFileApiInstance.ADexFile_Error_toString_ptr(self);
}

extern void ADexFileMethodCallbackWrapper(void* _Nullable data, const ADexFile_Method* _Nonnull method);
*/
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type DexSymbol struct {
	FilePath string
	Name     string
	Offset   uint64
	Size     uint64
}

type DexFile struct {
	api    *DexFileApi
	path   string
	offset uint64
	data   *[]byte
}

func tryNewDexFileFromRemoteMemory(offset uint64, size uint64, name string, mapping *process.Mapping, rm *remotememory.RemoteMemory) (*DexFile, error) {
	addr := libpf.Address(mapping.Vaddr + offset)
	data := make([]byte, size)
	if err := rm.Read(addr, data); err != nil {
		return nil, err
	}
	api, err := NewDexFileApi(unsafe.Pointer(&data[0]), size)
	if err != nil {
		return nil, fmt.Errorf("new dexfile api: %v", err)
	}
	return &DexFile{
		api:    api,
		path:   name,
		offset: offset,
		data:   &data,
	}, nil
}

func NewDexFile(offset uint64, size uint64, name string, mapping *process.Mapping, rm *remotememory.RemoteMemory) (*DexFile, error) {
	log.Infof("new dexfile offset: %v, size: %v, name: %s", offset, size, name)
	fileInfo, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	/*addr := libpf.Address(mapping.Vaddr + offset)
	data := make([]byte, size)
	if err := rm.Read(addr, data); err != nil {
		return nil, err
	}*/
	f, err := os.OpenFile(name, os.O_RDONLY, 0400)
	if err != nil {
		return nil, fmt.Errorf("openfile: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fsize := fi.Size()
	if offset+size > uint64(fsize) {
		return nil, fmt.Errorf("offset + size > filesize")
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(fsize), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("mmap: %v", err)
	}
	api, err := NewDexFileApi(unsafe.Pointer(&data[offset]), size)
	if err != nil {
		return tryNewDexFileFromRemoteMemory(offset, size, name, mapping, rm)
		//return nil, err
	}
	return &DexFile{
		api:    api,
		path:   name,
		offset: offset,
		data:   &data,
	}, nil
}

func (d *DexFile) FindSymbol(offset uint64) (*DexSymbol, error) {
	method := d.api.FindMethodAtOffset(offset)
	if method != nil {
		return &DexSymbol{
			FilePath: d.path,
			Offset:   method.GetCodeOffset(),
			Name:     method.GetName(),
			Size:     method.GetCodeSize(),
		}, nil
	}
	return nil, fmt.Errorf("symbol not found for offset:%v", offset)
}

func (d *DexFile) PrintAllMethod() {
	d.api.ForEachMethod(func(inner_d *DexFileApi, method DexFileMethodApi) {
		name, _ := method.GetQualifiedName()
		desc, _ := method.GetClassDescriptor()
		offset, size := method.GetCodeOffset()
		log.Infof("dexfile method [%#x:%#x] name:%v, desc:%v", offset, size, name, desc)
	})
}

type DexFileMethod struct {
	name   *C.char
	offset uint64
	size   uint64
}

func (m *DexFileMethod) GetName() string {
	return C.GoString(m.name)
}

func (m *DexFileMethod) GetCodeOffset() uint64 {
	return m.offset
}

func (m *DexFileMethod) GetCodeSize() uint64 {
	return m.size
}

type DexFileApi struct {
	self         *C.ADexFile
	callback     func(*DexFileApi, DexFileMethodApi)
	found_method DexFileMethod
}

func NewDexFileApi(addr unsafe.Pointer, file_size uint64) (*DexFileApi, error) {
	var cdexfile *C.ADexFile
	cfile_size := C.size_t(file_size)
	var cnew_size C.size_t
	clocation := C.CString("")
	defer C.free(unsafe.Pointer(clocation))
	err := NewDexFileError(C.ADexFile_create(addr, cfile_size, &cnew_size, clocation, &cdexfile))
	if !err.Ok() {
		return nil, fmt.Errorf("failed to create dexfile api: %d", err.Code())
	}
	api := &DexFileApi{self: cdexfile}
	runtime.SetFinalizer(api, func(d *DexFileApi) {
		if d.self != nil {
			C.ADexFile_destroy(d.self)
			d.self = nil
		}
	})
	log.Infof("create dexfile api addr:%#x, file_size:%v, new_size:%v, return dexfile:%v", addr, file_size, cnew_size, unsafe.Pointer(cdexfile))
	return api, nil
}

func (d *DexFileApi) FindMethodAtOffset(dex_pc uint64) *DexFileMethod {
	d.callback = func(inner_d *DexFileApi, method DexFileMethodApi) {
		name, _ := method.GetQualifiedName()
		offset, size := method.GetCodeOffset()
		log.Infof("found method at offset, name=%v", name)
		inner_d.found_method.name = name
		inner_d.found_method.offset = offset
		inner_d.found_method.size = size
	}
	var pinner runtime.Pinner
	pinner.Pin(d)
	pinner.Pin(&d.callback)
	pinner.Pin(C.ADexFileMethodCallbackWrapper)
	defer pinner.Unpin()
	//found := C.ADexFile_findMethodAtOffset(d.self, C.size_t(dex_pc), (*[0]byte)(C.ADexFileMethodCallbackWrapper), unsafe.Pointer(d))
	found := C.ADexFile_findMethodAtOffset(d.self, C.size_t(dex_pc), (*C.ADexFile_MethodCallback)(C.ADexFileMethodCallbackWrapper), unsafe.Pointer(d))
	if found != 0 {
		found_method := d.found_method
		return &found_method
	}
	return nil
}

func (d *DexFileApi) ForEachMethod(callback func(*DexFileApi, DexFileMethodApi)) {
	d.callback = callback
	//C.ADexFile_forEachMethod(d.self, (*[0]byte)(C.ADexFileMethodCallbackWrapper), unsafe.Pointer(d))
	C.ADexFile_forEachMethod(d.self, (*C.ADexFile_MethodCallback)(C.ADexFileMethodCallbackWrapper), unsafe.Pointer(d))
}

func (d *DexFileApi) doCallback(method DexFileMethodApi) {
	if d.callback != nil {
		d.callback(d, method)
	}
}

type DexFileMethodApi struct {
	self *C.ADexFile_Method
}

func NewDexFileMethod(method *C.ADexFile_Method) DexFileMethodApi {
	return DexFileMethodApi{self: method}
}

func (d *DexFileMethodApi) GetCodeOffset() (offset uint64, out_size uint64) {
	var c_out_size C.size_t
	offset = uint64(C.ADexFile_Method_getCodeOffset(d.self, &c_out_size))
	out_size = uint64(c_out_size)
	return
}

func (d *DexFileMethodApi) GetName() (name *C.char, out_size uint64) {
	var c_out_size C.size_t
	name = C.ADexFile_Method_getName(d.self, &c_out_size)
	out_size = uint64(c_out_size)
	return
}

func (d *DexFileMethodApi) GetQualifiedName() (name *C.char, out_size uint64) {
	var c_out_size C.size_t
	name = C.ADexFile_Method_getQualifiedName(d.self, 0, &c_out_size)
	out_size = uint64(c_out_size)
	return
}

func (d *DexFileMethodApi) GetClassDescriptor() (desc *C.char, out_size uint64) {
	var c_out_size C.size_t
	desc = C.ADexFile_Method_getClassDescriptor(d.self, &c_out_size)
	out_size = uint64(c_out_size)
	return
}

type DexFileError struct {
	self C.ADexFile_Error
}

func NewDexFileError(err C.ADexFile_Error) DexFileError {
	return DexFileError{self: err}
}

func (e *DexFileError) ToString() string {
	return C.GoString(C.ADexFile_Error_toString(e.self))
}

func (e *DexFileError) Ok() bool {
	return e.self == C.ADEXFILE_ERROR_OK
}

func (e *DexFileError) Code() uint32 {
	return uint32(e.self)
}

func TryLoadDexFileSupportLib(dir string) error {
	if C.DexFileApiInstance.loaded {
		return nil
	}
	return LoadDexFileSupportLib(dir)
}

func dlopen(lib_path string, mode C.int) (unsafe.Pointer, error) {
	path := C.CString(lib_path)
	defer C.free(unsafe.Pointer(path))
	handle := C.dlopen(path, mode)
	if handle == nil {
		return nil, fmt.Errorf("%v", C.GoString(C.dlerror()))
	}
	defer C.dlclose(handle)
	return handle, nil
}

func dlsym(handle unsafe.Pointer, name string) (unsafe.Pointer, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	sym := C.dlsym(handle, cname)
	if sym == nil {
		return nil, fmt.Errorf("%v", C.GoString(C.dlerror()))
	}
	return sym, nil
}

func LoadDexFileSupportLib(dir string) error {
	libPath := dir + "/libdexfiled.so"
	handle, err := dlopen(libPath, C.RTLD_LAZY)
	if err != nil {
		libPath = dir + "/libdexfile.so"
		handle, err = dlopen(libPath, C.RTLD_LAZY)
	}
	if err != nil {
		return fmt.Errorf("failed to load dexfile support lib: %v", err)
	}

	var ptr unsafe.Pointer
	ptr, err = dlsym(handle, "ADexFile_create")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_create_ptr = (C.ADexFile_create_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_destroy")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_destroy_ptr = (C.ADexFile_destroy_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_findMethodAtOffset")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_findMethodAtOffset_ptr = (C.ADexFile_findMethodAtOffset_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_forEachMethod")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_forEachMethod_ptr = (C.ADexFile_forEachMethod_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_Method_getCodeOffset")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_Method_getCodeOffset_ptr = (C.ADexFile_Method_getCodeOffset_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_Method_getName")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_Method_getName_ptr = (C.ADexFile_Method_getName_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_Method_getQualifiedName")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_Method_getQualifiedName_ptr = (C.ADexFile_Method_getQualifiedName_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_Method_getClassDescriptor")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_Method_getClassDescriptor_ptr = (C.ADexFile_Method_getClassDescriptor_func)(ptr)

	ptr, err = dlsym(handle, "ADexFile_Error_toString")
	if err != nil {
		return err
	}
	C.DexFileApiInstance.ADexFile_Error_toString_ptr = (C.ADexFile_Error_toString_func)(ptr)

	C.DexFileApiInstance.loaded = true
	return nil
}
