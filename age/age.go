// Package agetest embeds the age test vectors for use by Go programs.
package agetest

import (
	"embed"
	"io/fs"
)

// Vectors contains all the generated test vectors, one per file,
// in the root of the filesystem.
var Vectors fs.FS

//go:embed testdata
var testdata embed.FS

func init() {
	var err error
	Vectors, err = fs.Sub(testdata, "testdata")
	if err != nil {
		panic(err)
	}
}
