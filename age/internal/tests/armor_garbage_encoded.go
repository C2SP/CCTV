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
	f.X25519(testkit.TestX25519Identity)
	f.HMAC()
	f.Nonce()
	f.PayloadChunkFinal(testkit.ChunkSize)
	f.Buf.Write(f.Rand(20))
	f.ExpectPartialPayload(testkit.ChunkSize)
	file := f.Bytes()
	f.Buf.Reset()
	f.BeginArmor("AGE ENCRYPTED FILE")
	f.Body(file)
	f.Base64Padding()
	f.EndArmor("AGE ENCRYPTED FILE")
	f.Comment("there is trailing garbage encoded after the final chunk")
	f.Generate()
}
