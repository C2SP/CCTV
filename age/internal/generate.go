// Copyright 2022 The C2SP Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
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
	js := &strings.Builder{}
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
		fmt.Fprintf(js, "export { default as %s } from %q;\n", filepath.Base(vector), vector)
	}
	result := api.Build(api.BuildOptions{
		Stdin: &api.StdinOptions{
			Contents:   js.String(),
			ResolveDir: ".",
		},
		Loader: map[string]api.Loader{
			"": api.LoaderBinary,
		},
		Bundle:   true,
		Platform: api.PlatformNeutral,
		Target:   api.ES2022,
	})
	if len(result.Errors) != 0 {
		log.Fatal(result.Errors)
	}
	os.WriteFile("../index.js", result.OutputFiles[0].Contents, 0664)
}
