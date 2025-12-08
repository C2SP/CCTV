// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "c2sp.org/CCTV/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.Hybrid(testkit.TestHybridIdentity)
	body, args := f.UnreadLine(), f.UnreadLine()
	f.TextLine(args + " 1234")
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the mlkem768x25519 stanza has an unexpected extra argument")
	f.Generate()
}
