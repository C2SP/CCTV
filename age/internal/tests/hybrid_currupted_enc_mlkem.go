// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"

	"c2sp.org/CCTV/age/internal/testkit"
	"golang.org/x/crypto/curve25519"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	share, _ := curve25519.X25519(f.Rand(32), curve25519.Basepoint)
	f.HybridRecordIdentity(testkit.TestHybridIdentity)
	f.HybridStanza(share, f.Rand(32), testkit.TestHybridIdentity)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	enc, _ := base64.RawStdEncoding.DecodeString(args[1])
	enc[0] ^= 0xff
	f.TextLine("-> mlkem768x25519 " + base64.RawStdEncoding.EncodeToString(enc))
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	f.Comment("the ML-KEM part of enc is corrupted")
	f.Generate()
}
