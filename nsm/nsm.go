// +build enclave

package nsm

// #cgo LDFLAGS: -L. -lnsm
// #include "nsm.h"
import "C"

import (
	"bytes"
	"unsafe"
)

func GetDocument(pubBytes, userdata, nonce []byte) []byte {
	var userdataPtr *C.uchar
	if userdata != nil {
		userdataPtr = (*C.uchar)(unsafe.Pointer(&userdata[0]))
	}

	var noncePtr *C.uchar
	if nonce != nil {
		noncePtr = (*C.uchar)(unsafe.Pointer(&nonce[0]))
	}

	pubPointer := (*C.uchar)(unsafe.Pointer(&pubBytes[0]))

	fd := C.nsm_lib_init()
	defer C.nsm_lib_exit(fd)

	var att_doc_len C.uint = 16_384
	att_doc := make([]byte, att_doc_len)
	att_doc_ptr := (*C.uchar)(unsafe.Pointer(&att_doc[0]))

	resp := C.nsm_get_attestation_doc(
		fd, // fd
		userdataPtr, // user_data
		C.uint(len(userdata)), // user_data_len
		noncePtr, // nonce_data
		C.uint(len(nonce)), // nonce_len
		pubPointer, // pub_key_data
		C.uint(len(pubBytes)), // pub_key_len
		att_doc_ptr, // att_doc_data,
		&att_doc_len, // att_doc_len
	)

	if resp != 0 {
		panic("non-zero return code from nsm_get_attestation_doc()")
	}

	attlen := int(att_doc_len)

	doc := att_doc[:attlen]
	return doc
}

func GetRandomBytes(numBytes int) []byte {
	fd := C.nsm_lib_init()
	defer C.nsm_lib_exit(fd)

	fullBuffer := &bytes.Buffer{}

	for fullBuffer.Len() < numBytes {
		var bufLen C.ulong = 256
		buf := make([]byte, bufLen)
		bufPtr := (*C.uchar)(unsafe.Pointer(&buf[0]))

		resp := C.nsm_get_random(fd, bufPtr, &bufLen)
		if resp != 0 {
			panic("error getting random bytes")
		}

		fullBuffer.Write(buf[:bufLen])
	}

	respbuf := make([]byte, numBytes)
	copy(respbuf, fullBuffer.Bytes()[:numBytes])
	return respbuf
}
