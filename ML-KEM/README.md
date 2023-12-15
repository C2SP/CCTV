# ML-KEM Intermediate values

https://c2sp.org/CCTV/ML-KEM

This is a set of detailed test vectors for ML-KEM, as specified in
FIPS 203 (DRAFT).

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

* [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM)
    * Each file contains 100 randomly generated vectors.

The s2n-tls project includes
[vectors](https://github.com/aws/s2n-tls/tree/a6517c5fe97b1aa1898f2233498613dd53735bd8/tests/unit/kats)
for Kyber round 3 as well as some of the hybrid KEMs, including those used in
the TLS draft.
