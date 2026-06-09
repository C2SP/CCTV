# ML-KEM test vectors

[https://c2sp.org/CCTV/ML-KEM](https://c2sp.org/CCTV/ML-KEM)

This directory collects resources for testing (and developing) ML-KEM
implementations, as specified in FIPS 203.

In particular, it provides:

* Intermediate values for testing and debugging each intermediate step and
partial algorithm.

* Negative test vectors for invalid encapsulation keys.

* "Unlucky" vectors that require an unusually large number of XOF reads.

* Vectors that fail if `strcmp()` is used in ML-KEM.Decaps.

* Accumulated vectors (derived from the reference pq-crystals implementation)
for testing randomly reachable edge cases without checking in large amounts
of data, including an extended run of one million tests.

* References to other test vectors.

All test vectors are made available under the terms of the
[CC0 1.0](http://creativecommons.org/publicdomain/zero/1.0).

Implementers might also be interested in ["Enough Polynomials and Linear Algebra
to Implement Kyber"](https://words.filippo.io/kyber-math/).

### Changes from the FIPS 203 draft

Like the [official intermediate values][NIST vectors] from October 2023, all the
vectors in this directory implement the following two changes:

1. The order of the input i and j to the XOF at step 6 in Algorithm 12
   (K-PKE.KeyGen) is switched.
2. The order of the input i and j to the XOF at step 6 in Algorithm 13
   (K-PKE.Encrypt) is switched.

This reverts [an unintentional change][pqc-forum discussion] that is also reverted in the final document and makes K-PKE consistent with Kyber round 3.

Moreover, the value of `k` is now appended to the key seed `d` before deriving it with SHA3-512.

[NIST vectors]: https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
[pqc-forum discussion]: https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/s-C-zIAeKfE/m/eZJmXYsSAQAJ

## Intermediate values

The files in the `intermediate/` folder provide vectors for developing,
debugging, and testing ML-KEM step-by-step.

Each file lists every intermediate value of the ML-KEM.KeyGen, K-PKE.KeyGen,
ML-KEM.Encaps, K-PKE.Encrypt, ML-KEM.Decaps, and K-PKE.Decrypt algorithms, all
executed on the same set of keys and messages.

Byte strings are encoded in hex. Polynomials, NTT representatives, vectors, and
matrixes are encoded with ByteEncode12 and then in hex. Some polynomials are
also presented as an array of decimal coefficients to aid in the implementation
of ByteEncode, NTT, and Compress.

Where values appear multiple times across algorithms, they are not repeated in
the test files. uᵈ and vᵈ are the u and v values from K-PKE.Decrypt, after they
went through a Compress/Decompress cycle. (Props to the spec for maintaining a
consistent lexical scope across algorithms! The one exception is that r is
reused for the 32-byte K-PKE.Encrypt input and for the vector of polynomials
sampled from it. The two are easily distinguished.)

## Bad encapsulation keys

Section 6.2 of FIPS 203 ipd (ML-KEM Encapsulation) requires input validation on
the encapsulation key, checking that all encoded polynomial coefficients are
reduced modulo the field prime (the "*Modulus check*").

The files in the `modulus/` folder provide invalid ML-KEM.Encaps inputs,
hex-encoded, one per line. Every value in the range q to 2¹²-1 and every
position in the key is tested individually.

The vectors share most of the coefficients so that they compress from 1–3 MiB
down to 12–28 KiB.

## Unlucky NTT sampling vector

The SampleNTT algorithm reads a variable number of bytes from an Extendable
Output Function to perform rejection sampling. The files in the `unlucky/`
folder provide test vectors that cause many more rejections than usual.

In particular, these vectors require reading more than 575 bytes from the
SHAKE-128 XOF in SampleNTT, which would ordinarily happen [with probability
2⁻³⁸](https://www.wolframalpha.com/input?i=binomcdf%28384%2C+3329%2F4096%2C+255%29).

Note that these vectors can be run through a regular deterministic ML-KEM
testing API (i.e. one that injects the `d`, `z`, `m` random values) since they
were bruteforced at the level of the `d` value.

If for some reason an implementation needs to draw a fixed amount of bytes from
the XOF, at least 704 bytes are necessary for [a negligible probability (~
2⁻¹²⁸)](https://www.wolframalpha.com/input?i=binomcdf%28469%2C+3329%2F4096%2C+255%29)
of failure.

## `strcmp` vectors

In ML-KEM.Decaps the ciphertext is compared with the output of K-PKE.Encrypt for
implicit rejection. If an implementation were to use `strcmp()` for that
comparison it would fail to reject some ciphertexts if a zero byte terminates
the comparison early.

The files in the `strcmp/` folder provide test vectors that exercise this edge
case. The chance of it occurring randomly is 2⁻¹⁶, and it is not covered by the
pq-crystals vectors.

## Accumulated pq-crystals vectors

The `ref/test/test_vectors.c` program in the *standard* branch of
github.com/pq-crystals/kyber produces 10 000 randomly generated tests.
Thanks to the limited range of fundamental integer types (at most 0–4096), this
is sufficient to hit a lot of edge cases that don't need to be deliberately
targeted with specific test vectors.

The output of the three `test_vectors.c` programs amounts to 300MB. Instead of
checking in such a large amount of data, or running a binary as part of testing,
implementations can generate the test inputs from the deterministic RNG, and
check that the test outputs hash to the expected value.

The input format, output format, and output hash are provided below.

The deterministic RNG is a single SHAKE-128 instance with an empty input.
(The RNG stream starts with `7f9c2ba4e88f827d616045507605853e`.)

For each test, the following values are drawn from the RNG in order:

* `d` for K-PKE.KeyGen (don't forget to append `k` as the 33rd byte)
* `z` for ML-KEM.KeyGen
* `m` for ML-KEM.Encaps
* `ct` as an invalid ciphertext input to ML-KEM.Decaps

Then, the following values are written to a running SHAKE-128 instance in order:

* `ek` from ML-KEM.KeyGen
* `dk` from ML-KEM.KeyGen
* `ct` from ML-KEM.Encaps
* `k` from ML-KEM.Encaps (which should be checked to match the output of ML-KEM.Decaps when provided with the correct `ct`)
* `k` from ML-KEM.Decaps when provided with the random `ct`

The resulting hashes for 10 000 consecutive tests are:

* ML-KEM-512: `705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13`
* ML-KEM-768: `f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1`
* ML-KEM-1024: `e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5`

The resulting hashes for 1 000 000 consecutive tests are:

* ML-KEM-512: `21dd330d4355f2ae2876b9fa2b9de62ecaf76aca1d598de8db2b467d36e36a6a`
* ML-KEM-768: `3b108396a277f2952ff3243a985c9709bcb95788c39b7b36a2c4e19d1a41e51e`
* ML-KEM-1024: `6377c4f0ecfdb32e63f7b58227960828784fe0b3e0e5e5e9f77be300f003512a`

## Other Known Answer Tests

The following vectors also target FIPS 203 ipd with the Â fix described above.

* [NIST's Intermediate Values](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files)
    * Random values (such as d, z, and m) are equal. This is not spec compliant.

* [pq-crystals](https://github.com/pq-crystals/kyber), *standard* branch
    * `ref/test/test_vectors.c` generates 10 000 vectors randomly.
    * Accumulated vectors are available above.

* [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM)
    * Each file contains 100 randomly generated vectors.

The s2n-tls project includes
[vectors](https://github.com/aws/s2n-tls/tree/a6517c5fe97b1aa1898f2233498613dd53735bd8/tests/unit/kats)
for Kyber round 3 as well as some of the hybrid KEMs, including those used in
the TLS draft.
