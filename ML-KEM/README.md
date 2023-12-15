# ML-KEM Intermediate values

https://c2sp.org/CCTV/ML-KEM

The files in this directory are a set of detailed test vectors for ML-KEM, as
specified in FIPS 203 (DRAFT).

Like the [official intermediate values](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/example-files/PQC%20Intermediate%20Values.zip)
from October 2023, these vectors implement the following two changes:

1. The order of the input i and j to the XOF at step 6 in
    Algorithm 12 (K-PKE.KeyGen) is switched.
2. The order of the input i and j to the XOF at step 6 in
    Algorithm 13 (K-PKE.Encrypt) is switched.

This reverts [an unintentional change](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/s-C-zIAeKfE/m/eZJmXYsSAQAJ)
and makes K-PKE consistent with Kyber round 3.

Each file covers ML-KEM.KeyGen, K-PKE.KeyGen, ML-KEM.Encaps, K-PKE.Encrypt,
ML-KEM.Decaps, and K-PKE.Decrypt, all executed on the same set of keys and
messages.

Where values appear multiple times across algorithms, they are not repeated in
the test files. uᵈ and vᵈ are the u and v values from K-PKE.Decrypt, after they
went through a Compress/Decompress cycle. (Props to the spec for maintaining a
consistent lexical scope across algorithms! The one exception is that r is
reused for the 32-byte K-PKE.Encrypt input and for the vector of polynomials
sampled from it. The two are easily distinguished.)

Byte strings are encoded in hex. Polynomials, NTT representatives, vectors, and
matrixes are encoded with ByteEncode12 and then in hex. Some polynomials are
also presented as an array of decimal coefficients to aid in the implementation
of ByteEncode, NTT, and Compress.

Implementers might also be interested in ["Enough Polynomials and Linear Algebra
to Implement Kyber"](https://words.filippo.io/kyber-math/).

## Accumulated pq-crystals vectors

The `ref/test/test_vectors.c` program in the *standard* branch of
github.com/pq-crystals/kyber produces 10 000 randomly generated tests, amounting
to 300MB of output.

Instead of checking in such a large amount of data, or running a binary as part
of testing, implementations can generate the inputs from the deterministic RNG,
and check that the output hashes to the expected value.

The input format, as well as the output hash, are summarized below.

The deterministic RNG is SHAKE-128 with an empty input. The RNG stream starts
with `7f9c2ba4e88f827d616045507605853e`.

For each test, the following values are drawn from the RNG in order:

  * `d` for K-PKE.KeyGen
  * `z` for ML-KEM.KeyGen
  * `m` for ML-KEM.Encaps
  * `ct` as an invalid input to ML-KEM.Decaps

Then, the following values are written to a running SHAKE-128 instance in order:

  * `ek` from ML-KEM.KeyGen
  * `dk` from ML-KEM.KeyGen
  * `ct` from ML-KEM.Encaps
  * `k` from ML-KEM.Encaps (which should be checked to match the output of
    ML-KEM.Decaps when provided with the correct `ct`)
  * `k` from ML-KEM.Decaps when provided with the random `ct`

The resulting hashes for 10 000 consecutive tests are:

  * ML-KEM-512: `845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4`
  * ML-KEM-768: `f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3`
  * ML-KEM-1024: `47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543`

## Other Known Answer Tests

The following vectors target FIPS 203 ipd with the Â fix described above.

* [NIST's Intermediate Values](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files)
    * Random values (such as d, z, and m) are equal. This is not spec compliant.
    * Reproduced in the `NIST/` directory.

* [pq-crystals](https://github.com/pq-crystals/kyber), *standard* branch
    * First vector produced by `ref/test/test_vectors` reproduced in the
      `pq-crystals/` directory.
        * *Coins* (the concatenation of `d` and `z`), *Message*, and
          *Pseudorandom Ciphertext* were added to allow testing key generation,
          encapsulation, and failing decapsulation without reimplementing the RNG.
    * The test programs generate 10 000 vectors randomly.
    * Accumulated vectors are available above.

* [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM)
    * Each file contains 100 randomly generated vectors.

The s2n-tls project includes
[vectors](https://github.com/aws/s2n-tls/tree/a6517c5fe97b1aa1898f2233498613dd53735bd8/tests/unit/kats)
for Kyber round 3 as well as some of the hybrid KEMs, including those used in
the TLS draft.
