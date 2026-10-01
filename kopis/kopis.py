"""Reference implementation of the Kopis KEM, as specified in ``kopis-spec.md``.

Every function here corresponds to one in the specification, under the same
name, and carries the relevant spec text above it.  A ring element is a value
of type ``Rn``, holding the 256 canonical coefficients of the spec's ``Rn``;
multiplication is the naive negacyclic convolution.  Any input that does not
have the type the spec declares for it raises ``InvalidInput``.  This
implementation is written for clarity and for generating test vectors; it is
not constant time and MUST NOT be used in production.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from xoflib import turbo_shake128, turbo_shake256

# * `SK_SIZE = 32`
SK_SIZE = 32

# Domain separators:
#   * `DOMSEP_KGEXPAND = 0x01`
#   * `DOMSEP_GENMAT = 0x02`
#   * `DOMSEP_GENSEC = 0x03`
#   * `DOMSEP_PKHASH = 0x04`
#   * `DOMSEP_FO = 0x05`
#   * `DOMSEP_NOREJECT = 0x06`
DOMSEP_KGEXPAND = 0x01
DOMSEP_GENMAT = 0x02
DOMSEP_GENSEC = 0x03
DOMSEP_PKHASH = 0x04
DOMSEP_FO = 0x05
DOMSEP_NOREJECT = 0x06


# The spec gives every input a fixed type, e.g. `sk: [u8; 32]`,
# `ct: [u8; CT_SIZE]`, `v: VecR13` and `k: un`. The following report an input
# that does not have the type the spec declares for it.
class InvalidInput(ValueError):
    pass


def check_len(name: str, value, expected: int) -> None:
    if len(value) != expected:
        raise InvalidInput(f"{name} has length {len(value)}, expected {expected}")


def check_rn(name: str, value: Rn | VecRn, n: int) -> None:
    if value.n != n:
        raise InvalidInput(f"{name} is over R{value.n}, expected R{n}")


def check_un(name: str, value: int, n: int) -> None:
    if not 0 <= value < (1 << n):
        raise InvalidInput(f"{name} is {value}, expected a u{n} value")


# We use the TurboSHAKE XOF family defined in [RFC 9861]. We invoke it as
# `TurboSHAKE128/TurboSHAKE256(M, L, D)`, where `M` is the message to be
# hashed, `L` is the desired output length, and `D` is the domain separator in
# the range `[0x01, 0x7f]`.
def TurboSHAKE128(M: bytes, L: int, D: int) -> bytes:
    if not 0x01 <= D <= 0x7F:
        raise InvalidInput(f"D is {D}, expected a value in [0x01, 0x7f]")
    return turbo_shake128(D, bytes(M)).read(L)


def TurboSHAKE256(M: bytes, L: int, D: int) -> bytes:
    if not 0x01 <= D <= 0x7F:
        raise InvalidInput(f"D is {D}, expected a value in [0x01, 0x7f]")
    return turbo_shake256(D, bytes(M)).read(L)


# We define `to_bits_le(n: ℤ, k: un) -> [bool; n]` to be the function that
# converts an `n`-bit integer to its bit representation, starting with the
# least significant bit.
def to_bits_le(n: int, k: int) -> list[bool]:
    check_un("k", k, n)
    return [bool((k >> i) & 1) for i in range(n)]


# Similarly, we define `from_bits_le(n: ℤ, bits: [bool; n]) -> un` to interpret
# `n` bits as a `un` value, using `bits[0]` as the least significant bit of the
# output, and so on.
def from_bits_le(n: int, bits: list[bool]) -> int:
    check_len("bits", bits, n)
    return sum(1 << i for i in range(n) if bits[i])


# Let `R` be the negacyclic polynomial ring `ℤ[X]/(X²⁵⁶ + 1)`. We denote by
# `R13` the polynomial ring modulo `2^13`, i.e., `R/2¹³R` (this is isomorphic
# to `(ℤ/2¹³ℤ)[X]/(X²⁵⁶ + 1)`). Similarly, `R10` denotes `R/2¹⁰R` and `R1`
# denotes `R/2R`.
#
# For any modulus `N`, we say the canonical form of an element of `ℤ/Nℤ` is its
# representative integer in `[0, N)`.
class Rn:
    def __init__(self, n: int, coeffs: list[int]):
        check_len("coeffs", coeffs, 256)
        mod = 1 << n
        for coeff in coeffs:
            if coeff < 0 or coeff >= mod:
                raise InvalidInput(
                    f"Rn constructor got out-of-range coefficient {coeff}"
                )

        self.n = n
        self.mod = mod
        self.coeffs = [c % (1 << n) for c in coeffs]

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Rn) and self.n == other.n and self.coeffs == other.coeffs
        )

    def __add__(self, other: Rn) -> Rn:
        check_rn("other", other, self.n)
        return Rn(
            self.n, [(a + b) % self.mod for a, b in zip(self.coeffs, other.coeffs)]
        )

    def __sub__(self, other: Rn) -> Rn:
        check_rn("other", other, self.n)
        return Rn(
            self.n, [(a - b) % self.mod for a, b in zip(self.coeffs, other.coeffs)]
        )

    def __mul__(self, other: Rn) -> Rn:
        check_rn("other", other, self.n)

        acc = [0] * 512
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                acc[i + j] += (a * b) % self.mod
        return Rn(self.n, [(acc[k] - acc[k + 256]) % self.mod for k in range(256)])

    # For an element `r` in `Rn` and integer `N`, we define the right-shift
    # `r >> N` as `make_rn([a_0 >> N, a_1 >> N, ..., a_255 >> N])` where `a_i`
    # are the canonical coefficients of `r`.
    def __rshift__(self, N: int) -> Rn:
        return make_rn(self.n, [a >> N for a in canonical_coeffs(self)])

    # We define left-shift `r << N` similarly, with coefficients reduced mod
    # `2^n`.
    def __lshift__(self, N: int) -> Rn:
        return make_rn(self.n, [(a << N) % self.mod for a in canonical_coeffs(self)])

    # When we write `r as U` for some type `U`, we mean to invoke either the
    # natural injection or projection of `r` into/onto `U`. For example, if `r`
    # is in `VecR10` and `U` is `VecR13`, then it is the natural injection, and
    # if vice-versa, then it is the natural projection by quotienting by
    # `2¹⁰R13`.
    def as_rn(self, n: int) -> Rn:
        new_coeffs = [c % (1 << n) for c in canonical_coeffs(self)]
        return make_rn(n, new_coeffs)


# The type `VecRn` refers to `Rn^ℓ`, i.e., vectors of `ℓ` elements of `Rn`.
# When indexing into a vector `v: VecRn` for some `n`, we do so in the same
# order that was used in its constructor, i.e., `v[i]` equals `a[i]` where `a`
# is the input to the `make_vecn` that constructed `v`.
class VecRn:
    def __init__(self, n: int, elems: list[Rn]):
        for elem in elems:
            check_rn("elem", elem, n)

        self.n = n
        self.elems = list(elems)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, VecRn) and self.n == other.n and self.elems == other.elems
        )

    def __len__(self) -> int:
        return len(self.elems)

    def __getitem__(self, i: int) -> Rn:
        return self.elems[i]

    def __add__(self, other: VecRn) -> VecRn:
        check_rn("other", other, self.n)
        check_len("other", other, len(self.elems))

        return VecRn(self.n, [a + b for a, b in zip(self.elems, other.elems)])

    # We define right and left shift for elements of `VecRn` as operating
    # element-wise.
    def __rshift__(self, N: int) -> VecRn:
        return VecRn(self.n, [a >> N for a in self.elems])

    def __lshift__(self, N: int) -> VecRn:
        return VecRn(self.n, [a << N for a in self.elems])

    # When we write `r as U` for some type `U`, we mean to invoke either the
    # natural injection or projection of `r` into/onto `U`.
    def as_vecn(self, n: int) -> VecRn:
        return make_vecn(n, [a.as_rn(n) for a in self.elems])


# `transpose` transposes the given matrix or vector.
class RowVecRn:
    def __init__(self, n: int, elems: list[Rn]):
        for elem in elems:
            check_rn("elem", elem, n)

        self.n = n
        self.elems = list(elems)

    def __len__(self) -> int:
        return len(self.elems)

    def __mul__(self, v: VecRn) -> Rn:
        check_rn("v", v, self.n)
        check_len("v", v, len(self.elems))

        zero = make_rn(self.n, [0] * 256)
        return sum((self.elems[i] * v[i] for i in range(len(self.elems))), zero)


# The type `MatRn` refers to `Rn^(ℓ×ℓ)`, i.e., `ℓ×ℓ` matrices of elements of
# `Rn`, for any `n`.
class MatRn:
    def __init__(self, n: int, rows: list[list[Rn]]):
        for row in rows:
            check_len("row", row, len(rows))  # Matrix squareness check
            for elem in row:
                check_rn("elem", elem, n)

        self.n = n
        self.rows = [list(row) for row in rows]

    def __mul__(self, v: VecRn) -> VecRn:
        check_rn("v", v, self.n)
        check_len("v", v, len(self.rows))

        ell = len(self.rows)
        zero = make_rn(self.n, [0] * 256)
        return make_vecn(
            self.n,
            [
                sum((self.rows[i][j] * v[j] for j in range(ell)), zero)
                for i in range(ell)
            ],
        )


# For any `n`, we write `make_rn` to refer to the natural morphism from the
# space of coefficients `[un; 256]` to `Rn` (input is interpreted
# lowest-degree-coefficient-first).
def make_rn(n: int, coeffs: list[int]) -> Rn:
    return Rn(n, coeffs)


# `make_vecn` takes an array `[Rn; ℓ]` and interprets it as a column vector in
# `VecRn`, in the same order as `make_matn`, i.e., such that
# `make_matn([eye, zeros, ... zeros]) * make_vecn(eye) = make_vecn(eye)`, where
# `eye = [1, 0, ..., 0]`, and `zeros = [0, 0, ..., 0]`.
def make_vecn(n: int, elems: list[Rn]) -> VecRn:
    return VecRn(n, elems)


# `make_matn` takes a nested array `[[Rn; ℓ]; ℓ]` and interprets it as a list of
# rows in a matrix in `MatRn`.
def make_matn(n: int, rows: list[list[Rn]]) -> MatRn:
    return MatRn(n, rows)


# For any `n` and a ring element `r` we say its _canonical coefficients_
# `canonical_coeffs(r: Rn) -> [un; 256]` are the unique sequence of 256 `un`
# values `a_0, ..., a_255` such that `r = a_255 X^255 + ... + a_1 X + a_0`.
def canonical_coeffs(r: Rn) -> list[int]:
    # The coeffs in Rn are stored reduced mod-n, so nothing needs to be done
    return list(r.coeffs)


# `transpose` transposes the given matrix or vector.
def transpose(x: MatRn | VecRn) -> MatRn | RowVecRn:
    if isinstance(x, MatRn):
        ell = len(x.rows)
        return make_matn(x.n, [[x.rows[j][i] for j in range(ell)] for i in range(ell)])
    if isinstance(x, VecRn):
        return RowVecRn(x.n, x.elems)
    raise InvalidInput(f"x is a {type(x).__name__}, expected a MatRn or VecRn")


# Serializes an element of Rn (for any choice n=13,10,1,t)
#
# fn serialize_elem(n: ℤ, r: Rn) -> [u8; n*256/8]:
#   let a = canonical_coeffs(r)
#
#   let all_bits: [bool; n*256]
#   for i in 0..256:
#     all_bits[n*i..n*(i+1)] = to_bits_le(n, a[i])
#
#   let out: [u8; 32*n]
#   for i in 0..32*n:
#     out[i] = from_bits_le(8, all_bits[8*i..8*(i+1)])
#   return out
def serialize_elem(n: int, r: Rn) -> bytes:
    check_rn("r", r, n)

    a = canonical_coeffs(r)

    all_bits = [False] * (n * 256)
    for i in range(256):
        all_bits[n * i : n * (i + 1)] = to_bits_le(n, a[i])

    out = bytearray(32 * n)
    for i in range(32 * n):
        out[i] = from_bits_le(8, all_bits[8 * i : 8 * (i + 1)])
    return bytes(out)


# Deserializes an element of Rn (for any choice n=13,10,1,t)
#
# fn deserialize_elem(n: ℤ, bytes: [u8; n*256/8]) -> Rn:
#   let all_bits: [bool; n*256]
#   for i in 0..n*32:
#     all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])
#
#   let coeffs: [un; 256]
#   for i in 0..256:
#     coeffs[i] = from_bits_le(n, all_bits[n*i..n*(i+1)])
#   return make_rn(coeffs)
def deserialize_elem(n: int, bytes: bytes) -> Rn:
    check_len("bytes", bytes, n * 256 // 8)

    all_bits = [False] * (n * 256)
    for i in range(n * 32):
        all_bits[8 * i : 8 * (i + 1)] = to_bits_le(8, bytes[i])

    coeffs = [0] * 256
    for i in range(256):
        coeffs[i] = from_bits_le(n, all_bits[n * i : n * (i + 1)])
    return make_rn(n, coeffs)


# Returns the number of set bits in b
#
# fn hamming(b: [bool; μ/2]) -> u13:
#   let mut weight = 0u13
#   for i in 0..μ/2:
#     if b[i]:
#       weight += 1
#   return weight
def hamming(b: list[bool]) -> int:
    weight = 0
    for i in range(len(b)):
        if b[i]:
            weight += 1
    return weight


# The following variables represent security parameters, and depend on the
# security level being instantiated:
#
# * `ℓ` — The public matrix dimension. This impacts the size of public keys and
#   ciphertexts
# * `μ` — The binomial parameter used for secret generation. This is always
#   even.
# * `t` — The base-2 logarithm of the modulus of the space of compressed ring
#   elements
@dataclass(frozen=True)
class Kopis:
    name: str
    ell: int
    t: int
    mu: int

    # * `PK_SIZE = 256*ℓ*10/8 + 32`
    @property
    def PK_SIZE(self) -> int:
        return 256 * self.ell * 10 // 8 + 32

    # * `CT_SIZE = 256*t/8 + 256*ℓ*10/8`
    @property
    def CT_SIZE(self) -> int:
        return 256 * self.t // 8 + 256 * self.ell * 10 // 8

    # fn SkToPk(sk: [u8; 32]) -> [u8; PK_SIZE]:
    #   let (_, _, pk, _) = ExpandSecretKey(sk)
    #   return pk
    def SkToPk(self, sk: bytes) -> bytes:
        check_len("sk", sk, SK_SIZE)

        _, _, pk, _ = self.ExpandSecretKey(sk)
        return pk

    # fn PkeEncrypt(
    #   randomness: [u8; 32],
    #   pk: [u8; PK_SIZE],
    #   msg: [u8; 32]
    # ) -> [u8; CT_SIZE]:
    #   let vec_b = deserialize_vec(10, pk[..256*ℓ*10/8])
    #   let mat_seed = pk[256*ℓ*10/8..]
    #   let m = deserialize_elem(1, msg)
    #
    #   let mat_A = GenMat(mat_seed)
    #   let vec_sprime = GenSecret(randomness)
    #   let vec_bprime = CompressToR10(mat_A * vec_sprime)
    #   let vprime = transpose(vec_b) * (vec_sprime as VecR10)
    #   let cm = CompressToRt(vprime - ((m as R10) << 9))
    #
    #   let ct = serialize_vec(10, vec_bprime) || serialize_elem(t, cm)
    #   return ct
    def PkeEncrypt(self, randomness: bytes, pk: bytes, msg: bytes) -> bytes:
        check_len("randomness", randomness, 32)
        check_len("pk", pk, self.PK_SIZE)
        check_len("msg", msg, 32)

        vec_b = self.deserialize_vec(10, pk[: 256 * self.ell * 10 // 8])
        mat_seed = pk[256 * self.ell * 10 // 8 :]
        m = deserialize_elem(1, msg)

        mat_A = self.GenMat(mat_seed)
        vec_sprime = self.GenSecret(randomness)
        vec_bprime = self.CompressToR10(mat_A * vec_sprime)
        vprime = transpose(vec_b) * vec_sprime.as_vecn(10)
        cm = self.CompressToRt(vprime - (m.as_rn(10) << 9))

        ct = self.serialize_vec(10, vec_bprime) + serialize_elem(self.t, cm)
        return ct

    # fn PkeDecrypt(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
    #   let (vec_s, ...) = ExpandSecretKey(sk)
    #   let vec_bprime = deserialize_vec(10, ct[..256*ℓ*10/8])
    #   let cm = deserialize_elem(t, ct[256*ℓ*10/8..])
    #   let v = transpose(vec_bprime) * (vec_s as VecR10)
    #   let cm10 = (cm as R10) << (10 - t)
    #   let mprime = DecodeMsg(v - cm10)
    #   return serialize_elem(1, mprime)
    def PkeDecrypt(self, sk: bytes, ct: bytes) -> bytes:
        check_len("sk", sk, SK_SIZE)
        check_len("ct", ct, self.CT_SIZE)

        vec_s, *_ = self.ExpandSecretKey(sk)
        vec_bprime = self.deserialize_vec(10, ct[: 256 * self.ell * 10 // 8])
        cm = deserialize_elem(self.t, ct[256 * self.ell * 10 // 8 :])
        v = transpose(vec_bprime) * vec_s.as_vecn(10)
        cm10 = cm.as_rn(10) << (10 - self.t)
        mprime = self.DecodeMsg(v - cm10)
        return serialize_elem(1, mprime)

    # fn KemEncap(
    #   randomness: [u8; 32],
    #   pk: [u8; PK_SIZE]
    # ) -> ([u8; 32], [u8; CT_SIZE]):
    #   # Derive the output key and encryption randomness
    #   let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
    #   let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
    #   let (k, r) = (b[..32], b[32..])
    #
    #   # Encrypt to pk. `randomness` is itself the message
    #   let ct = PkeEncrypt(r, pk, randomness)
    #
    #   return (k, ct)
    def KemEncap(self, randomness: bytes, pk: bytes) -> tuple[bytes, bytes]:
        check_len("randomness", randomness, 32)
        check_len("pk", pk, self.PK_SIZE)

        pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
        b = TurboSHAKE256(randomness + pkh, 64, DOMSEP_FO)
        k, r = (b[:32], b[32:])

        ct = self.PkeEncrypt(r, pk, randomness)

        return (k, ct)

    # fn KemDecap(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
    #   let (_, z, pk, pkh) = ExpandSecretKey(sk)
    #
    #   let randomness = PkeDecrypt(sk, ct)
    #   let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
    #   let (k, rprime) = (b[..32], b[32..])
    #   let cprime = PkeEncrypt(rprime, pk, randomness)
    #
    #   if ct == cprime:
    #     return k
    #   else:
    #     return TurboSHAKE256(z || ct, 32, DOMSEP_NOREJECT)
    #
    # We note again that, along with all other top-level functions, `KemDecap`
    # MUST be constant time with respect to its inputs. In particular, an
    # implementer MUST perform the ciphertext equality check in constant time.
    def KemDecap(self, sk: bytes, ct: bytes) -> bytes:
        check_len("sk", sk, SK_SIZE)
        check_len("ct", ct, self.CT_SIZE)

        _, z, pk, pkh = self.ExpandSecretKey(sk)

        randomness = self.PkeDecrypt(sk, ct)
        b = TurboSHAKE256(randomness + pkh, 64, DOMSEP_FO)
        k, rprime = (b[:32], b[32:])
        cprime = self.PkeEncrypt(rprime, pk, randomness)

        # This is not a secure implementation of Kopis. We use an if-statement here
        if hmac.compare_digest(ct, cprime):
            return k
        else:
            return TurboSHAKE256(z + ct, 32, DOMSEP_NOREJECT)

    # fn ExpandSecretKey(
    #   sk: [u8; 32]
    # ) -> (VecR13, [u8; 32], [u8; PK_SIZE], [u8; 32]):
    #   let randomness = TurboSHAKE256(sk || (ℓ as u8), 96, DOMSEP_KGEXPAND)
    #   let mat_seed = randomness[..32]
    #   let secret_seed = randomness[32..64]
    #   let z = randomness[64..]
    #
    #   let mat_A = GenMat(mat_seed)
    #   let vec_s = GenSecret(secret_seed)
    #   let vec_b = CompressToR10(transpose(mat_A) * vec_s)
    #   let pk = serialize_vec(10, vec_b) || mat_seed
    #   let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
    #
    #   return (vec_s, z, pk, pkh)
    def ExpandSecretKey(self, sk: bytes) -> tuple[VecRn, bytes, bytes, bytes]:
        check_len("sk", sk, SK_SIZE)

        randomness = TurboSHAKE256(sk + bytes([self.ell]), 96, DOMSEP_KGEXPAND)
        mat_seed = randomness[:32]
        secret_seed = randomness[32:64]
        z = randomness[64:]

        mat_A = self.GenMat(mat_seed)
        vec_s = self.GenSecret(secret_seed)
        vec_b = self.CompressToR10(transpose(mat_A) * vec_s)
        pk = self.serialize_vec(10, vec_b) + mat_seed
        pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)

        return (vec_s, z, pk, pkh)

    # fn CompressToR10(v: VecR13) -> VecR10:
    #   let h1 = make_r13([4u13; 256])
    #   let h = make_vec13([h1; ℓ])
    #   let s = (v + h) >> 3
    #   return (s as VecR10)
    def CompressToR10(self, v: VecRn) -> VecRn:
        check_rn("v", v, 13)
        check_len("v", v, self.ell)

        h1 = make_rn(13, [4] * 256)
        h = make_vecn(13, [h1] * self.ell)
        s = (v + h) >> 3
        return s.as_vecn(10)

    # fn CompressToRt(r: R10) -> Rt:
    #   let h1 = make_r10([4u10; 256])
    #   let s = (r + h1) >> (10 - t)
    #   return (s as Rt)
    def CompressToRt(self, r: Rn) -> Rn:
        check_rn("r", r, 10)

        h1 = make_rn(10, [4] * 256)
        s = (r + h1) >> (10 - self.t)
        return s.as_rn(self.t)

    # fn DecodeMsg(r: R10) -> R1:
    #   let h2 = make_r10([2^8 - 2^(10-t-1) + 4; 256])
    #   let s = (r + h2) >> 9
    #   return (s as R1)
    def DecodeMsg(self, r: Rn) -> Rn:
        check_rn("r", r, 10)

        h2 = make_rn(10, [2**8 - 2 ** (10 - self.t - 1) + 4] * 256)
        s = (r + h2) >> 9
        return s.as_rn(1)

    # fn GenMat(seed: [u8; 32]) -> MatR13:
    #   let A: [[R13; ℓ]; ℓ]
    #   for i in 0u8..ℓ:
    #     for j in 0u8..ℓ:
    #       let buf = TurboSHAKE128(seed || i || j, 256*13/8, DOMSEP_GENMAT)
    #       A[i][j] = deserialize_elem(13, buf)
    #   return make_mat13(A)
    def GenMat(self, seed: bytes) -> MatRn:
        check_len("seed", seed, 32)

        A = [[None] * self.ell for _ in range(self.ell)]
        for i in range(self.ell):
            for j in range(self.ell):
                buf = TurboSHAKE128(
                    seed + bytes([i]) + bytes([j]), 256 * 13 // 8, DOMSEP_GENMAT
                )
                A[i][j] = deserialize_elem(13, buf)
        return make_matn(13, A)

    # fn GenSecret(seed: [u8; 32]) -> VecR13:
    #   let s: [R13; ℓ]
    #   for i in 0u8..ℓ:
    #     let buf = TurboSHAKE256(seed || i, μ*256/8, DOMSEP_GENSEC)
    #     let vals = bit_slices(buf)
    #     let r: [u13; 256]
    #     for k in 0..256:
    #       # Recall subtraction is wrapping
    #       r[k] = hamming(vals[2*k]) - hamming(vals[2*k+1])
    #     s[i] = make_r13(r)
    #   return make_vec13(s)
    def GenSecret(self, seed: bytes) -> VecRn:
        check_len("seed", seed, 32)

        s = [None] * self.ell
        for i in range(self.ell):
            buf = TurboSHAKE256(seed + bytes([i]), self.mu * 256 // 8, DOMSEP_GENSEC)
            vals = self.bit_slices(buf)
            r = [0] * 256
            for k in range(256):
                r[k] = (hamming(vals[2 * k]) - hamming(vals[2 * k + 1])) % (1 << 13)
            s[i] = make_rn(13, r)
        return make_vecn(13, s)

    # Serializes an element of VecRn (for any choice n=13,10,1,t)
    #
    # fn serialize_vec(n: ℤ, v: VecRn) -> [u8; ℓ*n*256/8]:
    #   let out: [u8; ℓ*n*32]
    #   for i in 0..ℓ:
    #     out[n*32*i..n*32*(i+1)] = serialize_elem(n, v[i])
    #   return out
    def serialize_vec(self, n: int, v: VecRn) -> bytes:
        check_rn("v", v, n)
        check_len("v", v, self.ell)

        out = bytearray(self.ell * n * 32)
        for i in range(self.ell):
            out[n * 32 * i : n * 32 * (i + 1)] = serialize_elem(n, v[i])
        return bytes(out)

    # Deserializes an element of VecRn (for any choice n=13,10,1,t)
    #
    # fn deserialize_vec(n: ℤ, bytes: [u8; ℓ*n*256/8]) -> VecRn:
    #   let elems: [Rn; ℓ]
    #   for i in 0..ℓ:
    #     elems[i] = deserialize_elem(n, bytes[n*32*i..n*32*(i+1)])
    #   return make_vecn(elems)
    def deserialize_vec(self, n: int, bytes: bytes) -> VecRn:
        check_len("bytes", bytes, self.ell * n * 256 // 8)

        elems = [None] * self.ell
        for i in range(self.ell):
            elems[i] = deserialize_elem(n, bytes[n * 32 * i : n * 32 * (i + 1)])
        return make_vecn(n, elems)

    # Reinterprets a bytestring as a sequence of bitstrings of length μ/2
    #
    # fn bit_slices(bytes: [u8; μ*256/8]) -> [[bool; μ/2]; 512]:
    #   let all_bits: [bool; μ*256]
    #   for i in 0..μ*32:
    #     all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])
    #
    #   let out: [[bool; μ/2]; 512]
    #   for i in 0..512:
    #     out[i] = all_bits[i*μ/2..(i+1)*μ/2]
    #   return out
    def bit_slices(self, bytes: bytes) -> list[list[bool]]:
        check_len("bytes", bytes, self.mu * 256 // 8)

        all_bits = [False] * (self.mu * 256)
        for i in range(self.mu * 32):
            all_bits[8 * i : 8 * (i + 1)] = to_bits_le(8, bytes[i])

        out = [None] * 512
        for i in range(512):
            out[i] = all_bits[i * self.mu // 2 : (i + 1) * self.mu // 2]
        return out


# |Name       | Parameters     | `PK_SIZE` | `CT_SIZE` | `SK_SIZE` |
# |---------- |----------------|-----------|-----------|-----------|
# |Kopis-512  | `ℓ=2 t=3 μ=10` | 672       | 736       | 32        |
# |Kopis-768  | `ℓ=3 t=4 μ=8`  | 992       | 1088      | 32        |
# |Kopis-1024 | `ℓ=4 t=6 μ=6`  | 1312      | 1472      | 32        |
KOPIS_512 = Kopis(name="kopis512", ell=2, t=3, mu=10)
KOPIS_768 = Kopis(name="kopis768", ell=3, t=4, mu=8)
KOPIS_1024 = Kopis(name="kopis1024", ell=4, t=6, mu=6)

PARAMS = {
    512: KOPIS_512,
    768: KOPIS_768,
    1024: KOPIS_1024,
}
