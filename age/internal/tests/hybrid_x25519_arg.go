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
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	f.Hybrid(testkit.TestHybridIdentity)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	f.ArgsLine("X25519", args[1])
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the X25519 stanza has a hybrid enc")
	f.Generate()
}
