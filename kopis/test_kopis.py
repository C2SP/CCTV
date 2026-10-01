"""Unit tests for the Kopis KEM reference implementation."""

from __future__ import annotations

import json
import os

import pytest
from xoflib import turbo_shake128

import kopis
from kopis import (
    DOMSEP_NOREJECT,
    InvalidInput,
    KOPIS_512,
    KOPIS_768,
    KOPIS_1024,
    PARAMS,
    TurboSHAKE128,
    TurboSHAKE256,
    canonical_coeffs,
    deserialize_elem,
    make_rn,
    serialize_elem,
)

ALL_LEVELS = [KOPIS_512, KOPIS_768, KOPIS_1024]
HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# TurboSHAKE: cross-check against RFC 9861 test vectors.
# ---------------------------------------------------------------------------


def test_turboshake128_rfc9861():
    assert (
        TurboSHAKE128(b"", 32, 0x1F).hex() == "1e415f1c5983aff2169217277d17bb53"
        "8cd945a397ddec541f1ce41af2c1b74c"
    )
    assert (
        TurboSHAKE128(bytes([0xFF, 0xFF, 0xFF]), 32, 0x07).hex()
        == "b658576001cad9b1e5f399a9f77723bb"
        "a05458042d68206f7252682dba3663ed"
    )


def test_turboshake256_rfc9861():
    assert (
        TurboSHAKE256(b"", 64, 0x1F).hex() == "367a329dafea871c7802ec67f905ae13"
        "c57695dc2c6663c61035f59a18f8e7db"
        "11edc0e12e91ea60eb6b32df06dd7f00"
        "2fbafabb6e13ec1cc20d995547600db0"
    )


# ---------------------------------------------------------------------------
# Serialization round-trips.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 3, 4, 6, 10, 13])
def test_serialize_deserialize_elem_roundtrip(n):
    rng = turbo_shake128(0x2A, f"elem-{n}".encode())
    mask = (1 << n) - 1
    # build a deterministic coefficient vector
    raw = rng.read(256 * 4)
    coeffs = [
        int.from_bytes(raw[4 * i : 4 * i + 4], "little") & mask for i in range(256)
    ]
    data = serialize_elem(n, make_rn(n, coeffs))
    assert len(data) == 256 * n // 8
    assert canonical_coeffs(deserialize_elem(n, data)) == coeffs


def test_serialize_deserialize_vec_roundtrip():
    k = KOPIS_768
    vec = kopis.make_vecn(
        10,
        [
            make_rn(10, [(i * 7 + j) % (1 << 10) for j in range(256)])
            for i in range(k.ell)
        ],
    )
    data = k.serialize_vec(10, vec)
    assert len(data) == k.ell * 256 * 10 // 8
    assert k.deserialize_vec(10, data) == vec


def test_deserialize_masks_to_n_bits():
    # 13-bit deserialization must never yield a value >= 2**13.
    data = bytes([0xFF]) * (256 * 13 // 8)
    coeffs = canonical_coeffs(deserialize_elem(13, data))
    assert all(c == (1 << 13) - 1 for c in coeffs)


# ---------------------------------------------------------------------------
# Ring arithmetic.
# ---------------------------------------------------------------------------


def test_mul_is_negacyclic():
    # X^255 * X = X^256 = -1  (mod X^256 + 1)
    a = [0] * 256
    a[255] = 1
    b = [0] * 256
    b[1] = 1
    expected = [0] * 256
    expected[0] = (-1) % (1 << 13)
    assert make_rn(13, a) * make_rn(13, b) == make_rn(13, expected)


def test_mul_identity():
    one = [0] * 256
    one[0] = 1
    a = make_rn(13, [(i * 3 + 1) % (1 << 13) for i in range(256)])
    assert a * make_rn(13, one) == a


# ---------------------------------------------------------------------------
# Sizes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "k,pk_size,ct_size",
    [
        (KOPIS_512, 672, 736),
        (KOPIS_768, 992, 1088),
        (KOPIS_1024, 1312, 1472),
    ],
)
def test_advertised_sizes(k, pk_size, ct_size):
    assert k.PK_SIZE == pk_size
    assert k.CT_SIZE == ct_size


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_output_sizes(k):
    sk = os.urandom(32)
    pk = k.SkToPk(sk)
    assert len(pk) == k.PK_SIZE
    ss, ct = k.KemEncap(os.urandom(32), pk)
    assert len(ss) == 32
    assert len(ct) == k.CT_SIZE
    assert len(k.KemDecap(sk, ct)) == 32


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_sk_to_pk_deterministic(k):
    sk = os.urandom(32)
    assert k.SkToPk(sk) == k.SkToPk(sk)


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_encap_deterministic_in_randomness(k):
    pk = k.SkToPk(os.urandom(32))
    randomness = os.urandom(32)
    assert k.KemEncap(randomness, pk) == k.KemEncap(randomness, pk)


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_domain_separation_by_level(k):
    # The same sk yields distinct expanded keys per parameter set because the
    # dimension ell is absorbed during key expansion.
    sk = bytes(range(32))
    pks = {kk.name: kk.SkToPk(sk) for kk in ALL_LEVELS}
    assert len(set(pks.values())) == len(ALL_LEVELS)


# ---------------------------------------------------------------------------
# Correctness (round-trip) and implicit rejection.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_roundtrip_random(k):
    sk = os.urandom(32)
    pk = k.SkToPk(sk)
    for _ in range(10):
        ss, ct = k.KemEncap(os.urandom(32), pk)
        assert k.KemDecap(sk, ct) == ss


# Roundtrip using odd secret keys
@pytest.mark.parametrize("k", ALL_LEVELS)
def test_roundtrip_edge_secret_keys(k):
    for sk in (bytes(32), bytes([0xFF] * 32), bytes(range(32))):
        pk = k.SkToPk(sk)
        ss, ct = k.KemEncap(os.urandom(32), pk)
        assert k.KemDecap(sk, ct) == ss


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_pke_roundtrip(k):
    sk = os.urandom(32)
    pk = k.SkToPk(sk)
    msg = os.urandom(32)
    ct = k.PkeEncrypt(os.urandom(32), pk, msg)
    assert k.PkeDecrypt(sk, ct) == msg


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_implicit_rejection(k):
    sk = os.urandom(32)
    pk = k.SkToPk(sk)
    ss, ct = k.KemEncap(os.urandom(32), pk)

    mauled = bytearray(ct)
    mauled[0] ^= 0x01
    mauled = bytes(mauled)

    # Mauling affects the shared secret
    dss = k.KemDecap(sk, mauled)
    assert dss != ss

    # The rejection value is TurboSHAKE256(z || ct, 32, DOMSEP_NOREJECT).
    _, z, _, _ = k.ExpandSecretKey(sk)
    assert dss == TurboSHAKE256(z + mauled, 32, DOMSEP_NOREJECT)


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_wrong_sk_decap_differs(k):
    sk = os.urandom(32)
    pk = k.SkToPk(sk)
    ss, ct = k.KemEncap(os.urandom(32), pk)
    other_sk = os.urandom(32)
    assert k.KemDecap(other_sk, ct) != ss


# ---------------------------------------------------------------------------
# Every input must have the length/type the spec declares for it.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [0, 31, 33, 64])
def test_wrong_length_sk_rejected(k, bad_len):
    sk = os.urandom(bad_len)
    with pytest.raises(InvalidInput):
        k.SkToPk(sk)
    with pytest.raises(InvalidInput):
        k.KemDecap(sk, bytes(k.CT_SIZE))


@pytest.mark.parametrize("k", ALL_LEVELS)
@pytest.mark.parametrize("delta", [-1, 1])
def test_wrong_length_pk_rejected(k, delta):
    pk = os.urandom(k.PK_SIZE + delta)
    with pytest.raises(InvalidInput):
        k.KemEncap(os.urandom(32), pk)
    with pytest.raises(InvalidInput):
        k.PkeEncrypt(os.urandom(32), pk, os.urandom(32))


@pytest.mark.parametrize("k", ALL_LEVELS)
@pytest.mark.parametrize("delta", [-1, 1])
def test_wrong_length_ct_rejected(k, delta):
    sk = os.urandom(32)
    ct = os.urandom(k.CT_SIZE + delta)
    with pytest.raises(InvalidInput):
        k.KemDecap(sk, ct)
    with pytest.raises(InvalidInput):
        k.PkeDecrypt(sk, ct)


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_empty_ct_rejected(k):
    with pytest.raises(InvalidInput):
        k.KemDecap(os.urandom(32), b"")


@pytest.mark.parametrize("k", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [31, 33, 48])
def test_wrong_length_encap_randomness_rejected(k, bad_len):
    pk = k.SkToPk(os.urandom(32))
    with pytest.raises(InvalidInput):
        k.KemEncap(os.urandom(bad_len), pk)


@pytest.mark.parametrize("k", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [31, 33])
def test_wrong_length_pke_msg_rejected(k, bad_len):
    pk = k.SkToPk(os.urandom(32))
    with pytest.raises(InvalidInput):
        k.PkeEncrypt(os.urandom(32), pk, os.urandom(bad_len))


@pytest.mark.parametrize("k", ALL_LEVELS)
def test_pk_for_another_parameter_set_rejected(k):
    sk = os.urandom(32)
    for other in ALL_LEVELS:
        if other is k:
            continue
        with pytest.raises(InvalidInput):
            k.KemEncap(os.urandom(32), other.SkToPk(sk))


@pytest.mark.parametrize("delta", [-1, 1])
def test_deserialize_elem_wrong_length_rejected(delta):
    with pytest.raises(InvalidInput):
        deserialize_elem(13, bytes(256 * 13 // 8 + delta))


def test_make_rn_wrong_coeff_count_rejected():
    with pytest.raises(InvalidInput):
        make_rn(13, [0] * 255)


def test_mismatched_ring_rejected():
    a = make_rn(13, [1] * 256)
    b = make_rn(10, [1] * 256)
    with pytest.raises(InvalidInput):
        a + b
    with pytest.raises(InvalidInput):
        a * b
    with pytest.raises(InvalidInput):
        serialize_elem(10, a)


# ---------------------------------------------------------------------------
# Generated test-vector files (if present) must agree with the implementation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_generated_vectors_consistent(level):
    path = os.path.join(HERE, f"test_vectors-kopis{level}.jsonl")
    if not os.path.exists(path):
        pytest.skip(f"{path} not generated; run gen_test_vectors.py first")

    k = PARAMS[level]
    with open(path) as f:
        vectors = [json.loads(line) for line in f if line.strip()]

    assert vectors, "vector file should not be empty"

    for v in vectors:
        sk = bytes.fromhex(v["sk"])
        pk = bytes.fromhex(v["pk"])
        encap_randomness = bytes.fromhex(v["encap_randomness"])
        encapper_ct = bytes.fromhex(v["encapper_ct"])
        decapper_ct = bytes.fromhex(v["decapper_ct"])
        encapper_ss = bytes.fromhex(v["encapper_ss"])
        decapper_ss = bytes.fromhex(v["decapper_ss"])

        if v["malformed"]:
            # Make sure we raise an error if inputs are malformed
            if len(sk) != kopis.SK_SIZE:
                with pytest.raises(InvalidInput):
                    k.SkToPk(sk)
            if len(encap_randomness) != 32 or len(pk) != k.PK_SIZE:
                with pytest.raises(InvalidInput):
                    k.KemEncap(encap_randomness, pk)
            if len(sk) != kopis.SK_SIZE or len(decapper_ct) != k.CT_SIZE:
                with pytest.raises(InvalidInput):
                    k.KemDecap(sk, decapper_ct)
        else:
            # Well-formed vector: the implementation must reproduce it exactly.
            assert len(sk) == kopis.SK_SIZE
            assert k.SkToPk(sk) == pk
            assert len(encap_randomness) == 32

            ss, ct = k.KemEncap(encap_randomness, pk)
            assert ss == encapper_ss
            assert ct == encapper_ct

            assert k.KemDecap(sk, decapper_ct) == decapper_ss

            if decapper_ct == encapper_ct:
                # Good vector: encapper and decapper shared secrets agree.
                assert decapper_ss == encapper_ss
            else:
                # Mauled vector: the decapper obtains a different shared secret.
                assert decapper_ss != encapper_ss


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_generated_vectors_have_all_categories(level):
    path = os.path.join(HERE, f"test_vectors-kopis{level}.jsonl")
    if not os.path.exists(path):
        pytest.skip(f"{path} not generated; run gen_test_vectors.py first")

    with open(path) as f:
        vectors = [json.loads(line) for line in f if line.strip()]

    descriptions = [v["description"] for v in vectors]
    assert any(d.startswith("good") for d in descriptions)
    assert any(d.startswith("mauled") for d in descriptions)
    assert any(v["malformed"] for v in vectors)
    # Malformed vectors carry a coerced-computation result, not an empty field.
    assert all(v["encapper_ss"] and v["decapper_ss"] for v in vectors if v["malformed"])
