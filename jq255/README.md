# Test Vectors for jq255e and jq255e

For each curve, the corresponding JSON file encodes a map from the _test
type_ (a symbolic string) to an array of _test values_. Each test value
is a map that contains at least a field called `id`; the contents of
`id` are the concatenation of the test type and the test number
(starting at 0). Other elements of a test value are byte strings (always
encoded as lowercase hexadecimal strings) and Boolean flags. Contents of
test values, for each test type, are described in the subsections below.

The `mktests-json.py` script (re)generates the JSON files (the process
is deterministic so the same values should always be obtained). The
`jq255test.py` script tests the jq255 implementation against the test
vectors. Both scripts assume that the reference implementation of
jq255 (i.e. `jq255.py`) is reachable; if necessary, copy it to this
directory.

## decode

Each `decode` test value contains:

  - `data`: byte string (32 bytes)
  - `decodable`: Boolean

`decodable` is `true` if the byte string can be decoded as a group
element, `false` otherwise.

## map

Each `map` test value contains:

  - `f`: byte string (32 bytes)
  - `p`: byte string (32 bytes)

`f` is an integer encoded in unsigned little endian convention; it
is to be interpreted as a field element by reducing it modulo the
field order. The resulting field element is mapped to a group element
with `map_to_jq255()`. The `p` value is the encoding of the resulting
group element.

## add

Each `add` test value contains:

  - `p1`: byte string (32 bytes)
  - `p2`: byte string (32 bytes)
  - `p3`: byte string (32 bytes)
  - `p4`: byte string (32 bytes)
  - `p5`: byte string (32 bytes)
  - `p6`: byte string (32 bytes)

The values are encodings of group elements `P1`, `P2`,... to `P6`. The
elements fulfill the following equations:

  - `P3 = P1 + P2`
  - `P4 = 2*P1`
  - `P5 = 2*P1 + P2`
  - `P6 = 2*P1 + 2*P2`

These tests allow checking that core addition and doubling formulas are
implemented correctly.

## mul

Each `mul` test value contains:

  - `p`: byte string (32 bytes)
  - `q`: byte string (32 bytes)
  - `s`: byte string (32 bytes)

`s` is an encoded scalar. `p` and `q` encode group elements `P` and `Q`,
such that `Q = s*P`.

## keygen

Each `keygen` test value contains:

  - `sk`: byte string (32 bytes)
  - `pk`: byte string (32 bytes)

`sk` is an encoded private key; `pk` is the encoding of the corresponding
public key. This exercises multiplications of the conventional generator
by a scalar.

## hashraw

Each `hashraw` test value contains:

  - `raw`: byte string (varying lengths, up to 100 bytes)
  - `p`: byte string (32 bytes)

`p` is the encoding of the group element obtained by applying
`hash_to_group()` to the `raw` input bytes (raw data input).

## hashph

Each `hashph` test value contains:

  - `hv`: byte string (32 bytes)
  - `p`: byte string (32 bytes)

`p` is the encoding of the group element obtained by applying
`hash_to_group()` to the hash value `hv` (pre-hashed data, `hv`
was obtained by applying BLAKE2s to a single byte containing the test
number).

## ECDH

Each `ECDH` test value contains:

  - `sk`: byte string (32 bytes)
  - `pk1`: byte string (32 bytes)
  - `sec1`: byte string (32 bytes)
  - `pk2`: byte string (32 bytes)
  - `sec2`: byte string (32 bytes)

`sk` is the encoding of a private key, from each a public key `Q`
can be obtained in the usual way (`Q = sk*G` with `G` being the
conventional group generator). `pk1` the the valid encoding of
another public key, while `pk2` is an invalid encoding. With these
values:

  - `ECDH(sk, Q, pk1)` returns `(sec1, True)` (valid ECDH, the
    `sec1` key is produced).
  - `ECDH(sk, Q, pk2)` returns `(sec2, False)` (invalid ECDH, since
    `pk2` cannot be decoded; the `sec2` key is produced).

## sign

Each `sign` test value contains:

  - `sk`: byte string (32 bytes)
  - `pk`: byte string (32 bytes)
  - `seed`: byte string (varying lengths, up to 19 bytes)
  - `msg`: byte string (8 or 9 bytes)
  - `hv`: byte string (32 bytes)
  - `sig`: byte string (48 bytes)

`sk` is an encoded private key, `pk` is the encoding of the
corresponding public key. `seed` is an arbitrary byte string. `msg`
is the encoding of the string "`sample xxx`" with `xxx` being replaced
with the test number in decimal. `hv` is BLAKE2s hash of `msg`.
Computing the signature on these elements yields the signature `sig`:

```
M = prepare_message_prehashed(hv, "blake2s")
sig = sign(sk, pk, M, seed)
```

Implementers are encouraged to perform the following checks:

  - `pk` matches the public key that can be derived from the private key `sk`.

  - `hv` is indeed the BLAKE2s hash of `msg`.

  - The exact value of `sig` is obtained, with the provided seed. This
    exercises the internal nonce generation process.

  - The verification algorithm (`verify(pk, sig, M)`) returns `True`
    (the signature is verified).

  - If either one byte of `sig` or one byte of `hv` is modified, then
    `verify(pk, sig, M)` returns `False`.
