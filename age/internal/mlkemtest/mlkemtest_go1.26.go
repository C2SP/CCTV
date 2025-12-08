//go:build go1.26

package mlkemtest

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
)

func Encapsulate768(ek *mlkem.EncapsulationKey768, rand []byte) (sharedKey, ciphertext []byte, err error) {
	return mlkemtest.Encapsulate768(ek, rand)
}

func Encapsulate1024(ek *mlkem.EncapsulationKey1024, rand []byte) (sharedKey, ciphertext []byte, err error) {
	return mlkemtest.Encapsulate1024(ek, rand)
}
