//go:build !go1.26 && fips140v1.0

package mlkemtest

import (
	"crypto/mlkem"
	"errors"
	"unsafe"
)

// Reach ungracefully into the internals of crypto/internal/fips140/mlkem to
// perform derandomized encapsulation, which will be exposed in Go 1.26.

func Encapsulate768(ek *mlkem.EncapsulationKey768, rand []byte) (sharedKey, ciphertext []byte, err error) {
	if len(rand) != 32 {
		return nil, nil, errors.New("invalid ML-KEM-768 randomness size")
	}
	key := (*mlkem768EncapsulationKey)(unsafe.Pointer(ek))
	sharedKey, ciphertext = mlkem768EncapsulateInternal(key.key, (*[32]byte)(rand))
	return sharedKey, ciphertext, nil
}

type mlkem768EncapsulationKey struct {
	key unsafe.Pointer // *crypto/internal/fips140/v1.0.0-c2097c7c/mlkem.EncapsulationKey768
}

//go:linkname mlkem768EncapsulateInternal crypto/internal/fips140/v1.0.0-c2097c7c/mlkem.(*EncapsulationKey768).EncapsulateInternal
func mlkem768EncapsulateInternal(ek unsafe.Pointer, m *[32]byte) (sharedKey, ciphertext []byte)

func Encapsulate1024(ek *mlkem.EncapsulationKey1024, rand []byte) (sharedKey, ciphertext []byte, err error) {
	if len(rand) != 32 {
		return nil, nil, errors.New("invalid ML-KEM-1024 randomness size")
	}
	key := (*mlkem1024EncapsulationKey)(unsafe.Pointer(ek))
	sharedKey, ciphertext = mlkem1024EncapsulateInternal(key.key, (*[32]byte)(rand))
	return sharedKey, ciphertext, nil
}

type mlkem1024EncapsulationKey struct {
	key unsafe.Pointer // *crypto/internal/fips140/v1.0.0-c2097c7c/mlkem.EncapsulationKey1024
}

//go:linkname mlkem1024EncapsulateInternal crypto/internal/fips140/v1.0.0-c2097c7c/mlkem.(*EncapsulationKey1024).EncapsulateInternal
func mlkem1024EncapsulateInternal(ek unsafe.Pointer, m *[32]byte) (sharedKey, ciphertext []byte)
