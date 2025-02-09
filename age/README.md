# age test vectors

This directory contains a large set of test vectors for the age file encryption
format, as well as a framework to easily generate them.

The test suite can be applied to any age implementation, regardless of the language
it's implemented in, and the level of abstraction of its interface.
For the simplest, most universal integration, the implementation can just attempt
to decrypt the test files, check the operation only succeeds if `expect` is
`success`, and compare the decrypted payload. Test vectors involving
unimplemented features (such as passphrase encryption or armoring) can be ignored.

These vectors can't be used to test the encryption direction end-to-end (because
there is no strict specification for how to [reproducibly inject randomness](
https://words.filippo.io/dispatches/avoid-the-randomness-from-the-sky/)
in the process), however, they can be used to test that parsing and encoding
operations round-trip in various edge cases. Specifically, `armored` vectors can
be used to test round-trips of armor decode/encode (accounting for CRLF/LF and
trailing and leading spaces tolerance), any vector that's not a `header failure`
can be used to test round-trips of header decode/encode, and any `success` vector
can be used to test round-trips of STREAM decrypt/encrypt (with the help of the
`file key`).

For an example of how to use this test suite, check [the reference Go
implementation](https://github.com/FiloSottile/age/blob/980763a/testkit_test.go).

## Accessing the test vectors

If testing a Go program, you can import the `c2sp.org/CCTV/age` module and use
the embedded filesystem.

If using npm, you can install the `cctv-age` package and use the module exports.

Otherwise, you can use `git-subtree` to include a copy of the vectors in your
project. The license allows this without attribution.

```
git fetch https://github.com/C2SP/CCTV
TEMPDIR=$(mktemp -d)
git worktree add $TEMPDIR FETCH_HEAD
SPLIT=$(cd $TEMPDIR && git subtree split -P age/testdata --annotate 'testkit: ')
git worktree remove $TEMPDIR
git subtree add -P testkit $SPLIT
```

To update the vectors, repeat the process with `git subtree merge` instead of
`git subtree add`.

## Test file format

Each file in the `testdata` folder is a separate test vector, meant to be
processed independently. Each vector is meant to test only one failure (or
success) scenario.

The file is in two parts: first a textual header, then an empty line, and then
an age encrypted file, possibly compressed. The textual header is a series of
key-value pairs, separated by a colon and a space, each on their own line.

The following header keys are defined. Files with unknown keys should be
ignored.

- `expect`

  This key defines what the result of decrypting the file should be.
  Distinguishing between different types of failure can be important to avoid
  masking what should be a lower-level error (for example, a parsing error) with
  a higher-level error (for example, incorrect HMAC because the incorrectly
  parsed file was re-encoded before calculating the HMAC). However, they might
  not map effectively to your API, in which case you should consider aliasing
  indistinguishable cases. It can take the following values.

  * `success`

    The file should decrypt correctly all the way to EOF, and the payload should
    match the expected hash (see below).

  * `no match`

    The header should parse successfully, but none of the recipient stanzas can
    be unwrapped.

  * `HMAC failure`

    The header should parse successfully, and a file key can be unwrapped, but
    the header HMAC should not match.

  * `header failure`

    The header should fail to parse successfully.

  * `payload failure`

    The header should parse successfully, and a file key can be unwrapped, but
    the STREAM-encrypted payload doesn't decrypt successfully all the way to
    EOF. **Whatever payload decrypted successfully before encountering the error
    must be checked against the payload hash (see below).**

  * `armor failure`

    The ASCII armor should fail to parse successfully.

- `compressed`

  This key will be `gzip` if the age encrypted file is compressed with gzip.
  Note that encrypted files usually don't compress well, but large test files in
  this collection are generated from plaintexts selected to make the ciphertext
  compressible. **Some of these files can be several megabytes once decompressed.**

- `payload`

  This is a hex-encoded SHA-256 hash of the payload. **All** the plaintext that
  would have been released to the application by the API must match this hash,
  even if the decryption eventually fails.

- `identity`

  This is a Bech32 encoded X25519 identity that should be used to unwrap
  recipient stanzas. This key can appear multiple times.

- `passphrase`

  This is a passphrase that should be used to unwrap `scrypt` recipient stanzas.
  This key can appear multiple times.

- `armored`

  This key will be `yes` if the file is supposed to be encoded in the optional
  ASCII armor.

- `file key`

  This is the hex-encoded file key, to aid debugging. This can be ignored.

- `comment`

  This is a textual comment that explains the vector. This can be ignored.

## The testkit framework

Every test vector in `testdata` is generated by a corresponding file in
`internal/tests`, using the framework in `internal/testkit`.

To generate the files, run

```
go generate ./...
```

## License

The vectors in the `testdata` folder and the files in this top-level directory
are available under the terms of the
[Zero-Clause BSD](https://opensource.org/licenses/0BSD) (reproduced below),
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/), or
[Unlicense](https://unlicense.org/) license, to your choice.

Copyright (c) 2022 The age Authors

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted.

**The software is provided "as is" and the author disclaims all warranties with
regard to this software including all implied warranties of merchantability and
fitness. In no event shall the author be liable for any special, direct,
indirect, or consequential damages or any damages whatsoever resulting from loss
of use, data or profits, whether in an action of contract, negligence or other
tortious action, arising out of or in connection with the use or performance of
this software.**
