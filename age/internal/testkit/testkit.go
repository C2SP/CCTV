// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testkit

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"c2sp.org/CCTV/age/internal/bech32"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

var TestFileKey = []byte("YELLOW SUBMARINE")

var _, TestX25519Identity, _ = bech32.Decode(
	"AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0")

var TestX25519Recipient, _ = curve25519.X25519(TestX25519Identity, curve25519.Basepoint)

const ChunkSize = 64 * 1024

func NotCanonicalBase64(s string) string {
	// Assuming there are spare zero bits at the end of the encoded bitstring,
	// the character immediately after in the alphabet compared to the last one
	// in the encoding will only flip the last bit to one, making the string a
	// non-canonical encoding of the same value.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	idx := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[idx+1])
}

type TestFile struct {
	Buf  bytes.Buffer
	Rand func(n int) []byte

	fileKey     []byte
	streamKey   []byte
	nonce       [12]byte
	payload     bytes.Buffer
	expect      string
	comment     string
	identities  []string
	passphrases []string
	armor       bool
}

func NewTestFile() *TestFile {
	c, _ := chacha20.NewUnauthenticatedCipher(
		[]byte("TEST RANDOMNESS TEST RANDOMNESS!"), make([]byte, chacha20.NonceSize))
	rand := func(n int) []byte {
		out := make([]byte, n)
		c.XORKeyStream(out, out)
		return out
	}
	return &TestFile{Rand: rand, expect: "success", fileKey: TestFileKey}
}

func (f *TestFile) FileKey(key []byte) {
	f.fileKey = key
}

func (f *TestFile) TextLine(s string) {
	f.Buf.WriteString(s)
	f.Buf.WriteString("\n")
}

func (f *TestFile) UnreadLine() string {
	buf := bytes.TrimSuffix(f.Buf.Bytes(), []byte("\n"))
	idx := bytes.LastIndex(buf, []byte("\n")) + 1
	f.Buf.Reset()
	f.Buf.Write(buf[:idx])
	return string(buf[idx:])
}

func (f *TestFile) VersionLine(v string) {
	f.TextLine("age-encryption.org/" + v)
}

func (f *TestFile) ArgsLine(args ...string) {
	f.TextLine(strings.Join(append([]string{"->"}, args...), " "))
}

func (f *TestFile) UnreadArgsLine() []string {
	line := strings.TrimPrefix(f.UnreadLine(), "-> ")
	return strings.Split(line, " ")
}

var b64 = base64.RawStdEncoding.EncodeToString

func (f *TestFile) Body(body []byte) {
	for {
		line := body
		if len(line) > 48 {
			line = line[:48]
		}
		f.TextLine(b64(line))
		body = body[len(line):]
		if len(line) < 48 {
			break
		}
	}
}

func (f *TestFile) Base64Padding() {
	line := f.UnreadLine()
	paddingLen := 4 - len(line)%4
	if paddingLen == 4 {
		paddingLen = 0
	}
	padding := strings.Repeat("=", paddingLen)
	f.TextLine(line + padding)
}

func (f *TestFile) AEADBody(key, body []byte) {
	aead, _ := chacha20poly1305.New(key)
	f.Body(aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), body, nil))
}

func x25519(scalar, point []byte) []byte {
	secret, err := curve25519.X25519(scalar, point)
	if err != nil {
		if strings.Contains(err.Error(), "low order point") {
			return make([]byte, 32)
		}
		panic(err)
	}
	return secret
}

func (f *TestFile) X25519(identity []byte) {
	f.X25519RecordIdentity(identity)
	f.X25519NoRecordIdentity(identity)
}

func (f *TestFile) X25519RecordIdentity(identity []byte) {
	id, _ := bech32.Encode("AGE-SECRET-KEY-", identity)
	f.identities = append(f.identities, id)
}

func (f *TestFile) X25519NoRecordIdentity(identity []byte) {
	share := x25519(f.Rand(32), curve25519.Basepoint)
	f.X25519Stanza(share, identity)
}

func (f *TestFile) X25519Stanza(share, identity []byte) {
	recipient := x25519(identity, curve25519.Basepoint)
	f.ArgsLine("X25519", b64(share))
	// This would be ordinarily done as [ephemeral]recipient rather than
	// [identity]share, but for some tests we don't have the dlog of share.
	secret := x25519(identity, share)
	key := make([]byte, 32)
	hkdf.New(sha256.New, secret, append(share, recipient...),
		[]byte("age-encryption.org/v1/X25519")).Read(key)
	f.AEADBody(key, f.fileKey)
}

func (f *TestFile) Scrypt(passphrase string, workFactor int) {
	f.ScryptRecordPassphrase(passphrase)
	f.ScryptNoRecordPassphrase(passphrase, workFactor)
}

func (f *TestFile) ScryptRecordPassphrase(passphrase string) {
	f.passphrases = append(f.passphrases, passphrase)
}

func (f *TestFile) ScryptNoRecordPassphrase(passphrase string, workFactor int) {
	salt := f.Rand(16)
	f.ScryptNoRecordPassphraseWithSalt(passphrase, workFactor, salt)
}

func (f *TestFile) ScryptNoRecordPassphraseWithSalt(passphrase string, workFactor int, salt []byte) {
	f.ArgsLine("scrypt", b64(salt), strconv.Itoa(workFactor))
	key, err := scrypt.Key([]byte(passphrase), append([]byte("age-encryption.org/v1/scrypt"), salt...),
		1<<workFactor, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	f.AEADBody(key, f.fileKey)
}

func (f *TestFile) HMACLine(h []byte) {
	f.TextLine("--- " + b64(h))
}

func (f *TestFile) HMAC() {
	key := make([]byte, 32)
	hkdf.New(sha256.New, f.fileKey, nil, []byte("header")).Read(key)
	h := hmac.New(sha256.New, key)
	h.Write(f.Buf.Bytes())
	h.Write([]byte("---"))
	f.HMACLine(h.Sum(nil))
}

func (f *TestFile) Nonce() {
	nonce := f.Rand(16)
	f.streamKey = make([]byte, 32)
	hkdf.New(sha256.New, f.fileKey, nonce, []byte("payload")).Read(f.streamKey)
	f.Buf.Write(nonce)
}

func (f *TestFile) PayloadChunk(size int) {
	plaintext := bytes.Repeat([]byte{0}, size)
	s, _ := chacha20.NewUnauthenticatedCipher(f.streamKey, f.nonce[:])
	s.SetCounter(1)
	s.XORKeyStream(plaintext, plaintext)
	f.payloadChunk(plaintext)
}

func (f *TestFile) payloadChunk(plaintext []byte) {
	f.payload.Write(plaintext)
	aead, _ := chacha20poly1305.New(f.streamKey)
	f.Buf.Write(aead.Seal(nil, f.nonce[:], plaintext, nil))

	for i := 10; i >= 0; i-- {
		f.nonce[i]++
		if f.nonce[i] != 0 {
			break
		}
	}
}

func (f *TestFile) PayloadChunkFinal(size int) {
	f.nonce[11] = 1
	f.PayloadChunk(size)
}

func (f *TestFile) Payload(plaintext string) {
	f.Nonce()
	f.nonce[11] = 1
	f.payloadChunk([]byte(plaintext))
}

func (f *TestFile) ExpectHeaderFailure() {
	f.expect = "header failure"
}

func (f *TestFile) ExpectArmorFailure() {
	f.armor = true
	f.expect = "armor failure"
}

func (f *TestFile) ExpectPayloadFailure() {
	f.expect = "payload failure"
	f.payload.Reset()
}

func (f *TestFile) ExpectPartialPayload(goodBytes int) {
	f.expect = "payload failure"
	payload := f.payload.Bytes()
	f.payload.Reset()
	f.payload.Write(payload[:goodBytes])
}

func (f *TestFile) ExpectHMACFailure() {
	f.expect = "HMAC failure"
}

func (f *TestFile) ExpectNoMatch() {
	f.expect = "no match"
}

func (f *TestFile) Comment(c string) {
	f.comment = c
}

func (f *TestFile) BeginArmor(t string) {
	f.armor = true
	f.TextLine("-----BEGIN " + t + "-----")
}

func (f *TestFile) EndArmor(t string) {
	f.armor = true
	f.TextLine("-----END " + t + "-----")
}

func (f *TestFile) Bytes() []byte {
	out := make([]byte, f.Buf.Len())
	copy(out, f.Buf.Bytes())
	return out
}

func (f *TestFile) Generate() {
	fmt.Printf("expect: %s\n", f.expect)
	if f.expect == "success" || f.expect == "payload failure" {
		fmt.Printf("payload: %x\n", sha256.Sum256(f.payload.Bytes()))
	}
	fmt.Printf("file key: %x\n", f.fileKey)
	for _, id := range f.identities {
		fmt.Printf("identity: %s\n", id)
	}
	for _, p := range f.passphrases {
		fmt.Printf("passphrase: %s\n", p)
	}
	if f.armor {
		fmt.Printf("armored: yes\n")
	}
	if f.comment != "" {
		fmt.Printf("comment: %s\n", f.comment)
	}
	out := io.Writer(os.Stdout)
	if f.Buf.Len() > 1024 {
		fmt.Printf("compressed: zlib\n")
		out, _ = zlib.NewWriterLevel(os.Stdout, zlib.BestCompression)
		defer out.(*zlib.Writer).Close()
	}
	fmt.Println()
	io.Copy(out, &f.Buf)
}
