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

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	var max int
	d := make([]byte, 32)
	for {
		rand.Read(d)
		samples := sampleNTT(d)
		if samples > max {
			max = samples
			// 518aa157193090c8bb464f8f645ed3ea4e0bbfe6cda70f86f9768782321f1f2d: 380 samples
			// 851cf0ee43b802c538e5b4ee4d1991a28af90eeb87fe34d54095332821e65730: 381 samples
			// 8c7238e1965ddd73b1114b897e1bf4b308c0d9cc710d0482ab8b9e737405354a: 384 samples
			fmt.Printf("%x: %d samples\n", d, samples)
		}
	}
}

const (
	n = 256
	q = 3329
)

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
