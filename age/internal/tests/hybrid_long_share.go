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
	f.TextLine("-> mlkem768x25519 " + base64.RawStdEncoding.EncodeToString(append(enc, 0x00)))
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("an extra most-significant zero byte is appended to the X25519 part of enc")
	f.Generate()
}
