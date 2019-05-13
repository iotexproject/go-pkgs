// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package byteutil

import (
	"encoding/binary"
)

var machineEndian = binary.LittleEndian

// Uint32ToBytes converts a uint32 to 4 bytes with the machine endian
func Uint32ToBytes(value uint32) []byte {
	bytes := make([]byte, 4)
	machineEndian.PutUint32(bytes, value)
	return bytes
}

// Uint64ToBytes converts a uint64 to 8 bytes with the machine endian
func Uint64ToBytes(value uint64) []byte {
	bytes := make([]byte, 8)
	machineEndian.PutUint64(bytes, value)
	return bytes
}

// BytesToUint32 converts 4 bytes to uint32 with the machine endian
func BytesToUint32(value []byte) uint32 {
	return machineEndian.Uint32(value)
}

// BytesToUint64 converts 8 bytes to uint64 with the machine endian
func BytesToUint64(value []byte) uint64 {
	return machineEndian.Uint64(value)
}

// Must is a helper wraps a call to a function returing ([]byte, error) and panics if the error is not nil.
func Must(d []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return d
}
