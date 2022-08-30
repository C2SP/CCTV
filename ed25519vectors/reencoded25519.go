// Copyright 2022 Filippo Valsorda
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// ReencodedVerify is an Ed25519 verifier that accepts non-canonical R and A
// values, but then hashes the canonical versions into k.
//
// This verifier would appear to not have malleability issues if the test
// vectors don't target its behavior.
func ReencodedVerify(publicKey, message, sig []byte) bool {
	A, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	S, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(A.Bytes())
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k := new(edwards25519.Scalar).SetUniformBytes(hramDigest)

	// [8][S]B = [8]R + [8][k]A --> [8]([k](-A) + [S]B) = [8]R
	minusA := new(edwards25519.Point).Negate(A)
	RR := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, minusA, S)

	RR.MultByCofactor(RR)
	R.MultByCofactor(R)

	return RR.Equal(R) == 1
}
