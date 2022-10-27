// Copyright 2022 The C2SP Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:generate go run generate.go

func main() {
	log.SetFlags(0)
	tests, err := filepath.Glob("../testdata/*")
	if err != nil {
		log.Fatal(err)
	}
	for _, test := range tests {
		os.Remove(test)
	}
	generators, err := filepath.Glob("tests/*.go")
	if err != nil {
		log.Fatal(err)
	}
	for _, generator := range generators {
		vector := strings.TrimSuffix(generator, ".go")
		vector = "../testdata/" + strings.TrimPrefix(vector, "tests/")
		log.Printf("%s -> %s\n", generator, vector)
		out, err := exec.Command("go", "run", generator).Output()
		if err != nil {
			if err, ok := err.(*exec.ExitError); ok {
				log.Fatalf("%s", err.Stderr)
			}
			log.Fatal(err)
		}
		os.WriteFile(vector, out, 0664)
	}
}
