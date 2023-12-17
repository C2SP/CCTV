package main

import (
	"flag"
	"fmt"
	"math/rand"
)

const (
	n = 256
	q = 3329

	encodingSize12 = n * 12 / 8
)

var shortFlag = flag.Bool("short", false, "generate the short subset")
var kFlag = flag.Int("k", 3, "2 for -512, 3 for -768, 4 for -1024")

func main() {
	flag.Parse()
	for i := 0; i < *kFlag; i++ {
		genVector(func(t [][n]uint16) { t[i][0] = q })
		genVector(func(t [][n]uint16) { t[i][255] = q })
		genVector(func(t [][n]uint16) { t[i][0] = 1<<12 - 1 })
		genVector(func(t [][n]uint16) { t[i][255] = 1<<12 - 1 })
	}
	if !*shortFlag {
		var i, j int
		var x uint16 = q
		var doneValues, donePositions bool
		for {
			genVector(func(t [][n]uint16) { t[i][j] = x })
			x++
			if x == 1<<12 {
				x = q
				doneValues = true
			}
			j++
			if j == n {
				j = 0
				i++
			}
			if i == *kFlag {
				i = 0
				donePositions = true
			}
			if doneValues && donePositions {
				break
			}
		}
	}
}

func genVector(f func([][n]uint16)) {
	t := make([][n]uint16, *kFlag)
	for i := range t {
		t[i] = r[i]
	}
	f(t)
	out := make([]byte, 0)
	for i := range t {
		out = polyByteEncode(out, t[i])
	}
	out = append(out, ρ...)
	fmt.Printf("%x\n", out)
}

var r = [4][n]uint16{randomPoly(), randomPoly(), randomPoly(), randomPoly()}
var ρ = make([]byte, 32)

func init() { rand.Read(ρ) }

func randomPoly() [n]uint16 {
	var f [n]uint16
	for i := range f {
		f[i] = uint16(rand.Intn(q))
	}
	return f
}

// polyByteEncode appends the 384-byte encoding of f to b.
//
// It implements ByteEncode₁₂, according to FIPS 203 (DRAFT), Algorithm 4.
func polyByteEncode(b []byte, f [n]uint16) []byte {
	out, B := sliceForAppend(b, encodingSize12)
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		B[0] = uint8(x)
		B[1] = uint8(x >> 8)
		B[2] = uint8(x >> 16)
		B = B[3:]
	}
	return out
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
