// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"
	"encoding/hex"

	"c2sp.org/CCTV/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	share, _ := hex.DecodeString("97ba38a135fd5f9137fca3836bfec24340ab03d7ca316b26f482636334a52600")
	f.HybridRecordIdentity(testkit.TestHybridIdentity)
	f.HybridStanza(share, f.Rand(32), testkit.TestHybridIdentity)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	enc, _ := base64.RawStdEncoding.DecodeString(args[1])
	if enc[len(enc)-1] != 0x00 {
		panic("expected trailing zero byte")
	}
	f.TextLine("-> mlkem768x25519 " + base64.RawStdEncoding.EncodeToString(enc[:len(enc)-1]))
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("a trailing zero is missing from the X25519 part of enc")
	f.Generate()
}
