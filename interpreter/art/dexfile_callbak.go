package art

/*
#include "dex_file_external.h"
*/
import "C"
import (
	"unsafe"
)

//export ADexFileMethodCallbackWrapper
func ADexFileMethodCallbackWrapper(data unsafe.Pointer, method *C.ADexFile_Method) {
	api := (*DexFileApi)(data)
	api.doCallback(NewDexFileMethod(method))
}
