# ML-KEM Intermediate values

https://c2sp.org/CCTV/ML-KEM

This is a set of detailed test vectors for ML-KEM, as specified in
FIPS 203 (DRAFT).

Like the [official intermediate values](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/example-files/PQC%20Intermediate%20Values.zip)
from October 2023, these vectors implement the following two changes:

1. The order of the input i and j to the XOF at step 6 in
    Algorithm 12 K-PKE.KeyGen() is switched.
2. The order of the input i and j to the XOF at step 6 in
    Algorithm 13 K-PKE.Encrypt() is switched.

This reverts [an unintentional change](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/s-C-zIAeKfE/m/eZJmXYsSAQAJ)
and makes K-PKE consistent with Kyber round 3.

Each file covers KeyGen, Encrypt, Encaps, Decrypt, and Decaps, all executed on
the same set of keys and messages.

Where values appear multiple times across algorithms, they are not repeated in
the test files. (Props to the spec for maintaining a consistent lexical scope
across algorithms! The one exception is that r is reused for the 32-byte
K-PKE.Encrypt input and for the vector of polynomials sampled from it. The two
are easily distinguished.)

Byte strings are encoded in hex. Polynomials, NTT representatives, vectors, and
matrixes are encoded with ByteEncode12 and then in hex. Some polynomials are
also presented as an array of decimal coefficients to aid in the implementation
of ByteEncode, NTT, and Compress.
