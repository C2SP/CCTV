package main

import (
	"encoding/binary"
	"fmt"
	"log"
	rand "math/rand"
	"net/http"
	_ "net/http/pprof"

	"golang.org/x/crypto/sha3"
)

const (
	n = 256
	q = 3329
	k = 2 // Change depending on parameter set! {2, 3, 4} for ML-KEM-{512,768,1024}
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	var max int
	d := make([]byte, 33)
	for {
		rand.Read(d[:32])
		d[32] = k
		samples := sampleNTT(d)
		if samples > max || samples >= 384 {
			max = samples
			fmt.Printf("%x: %d samples (k = %d)\n", d[:32], samples, k)
		}

	}
}

func sampleNTT(d []byte) int {
	G := sha3.Sum512(d)
	rho := G[:32]

	B := sha3.NewShake128()
	B.Write(rho)
	B.Write([]byte{0, 0})

	var samples int
	var j int
	var buf [24]byte // buffered reads from B
	off := len(buf)  // index into buf, starts in a "buffer fully consumed" state
	for {
		if off >= len(buf) {
			B.Read(buf[:])
			off = 0
		}
		d1 := binary.LittleEndian.Uint16(buf[off:]) & 0b1111_1111_1111
		d2 := binary.LittleEndian.Uint16(buf[off+1:]) >> 4
		off += 3
		samples++
		if d1 < q {
			j++
		}
		if j == n {
			break
		}
		samples++
		if d2 < q {
			j++
		}
		if j == n {
			break
		}
	}
	return samples
}
