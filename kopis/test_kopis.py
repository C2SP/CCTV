import json
import os

import pytest
from xoflib import turbo_shake128

import kopis
from kopis import (
    DOMSEP_NOREJECT,
    KOPIS_512,
    KOPIS_768,
    KOPIS_1024,
    PARAMS,
    InvalidInput,
    TurboSHAKE256,
    canonical_coeffs,
    deserialize_elem,
    make_rn,
    serialize_elem,
)

ALL_LEVELS = [KOPIS_512, KOPIS_768, KOPIS_1024]
ALL_MODULI = [1, 3, 4, 6, 10, 13]
HERE = os.path.dirname(os.path.abspath(__file__))


# Produces a deterministic RNG given a pytest context. This is a fixture, so any time you see `rng`
# in the args of a test function, that means this function is called with the caller's context, and
# the output is bound to `rng`. So when `rng` is called below, it's really calling `xof.read`.
@pytest.fixture
def rng(request):
    """Deterministic replacement for ``os.urandom``: a TurboSHAKE128 sponge seeded
    with this test's own node id, so every test is reproducible on its own."""
    xof = turbo_shake128(0x1F, f"kopis unit tests :: {request.node.nodeid}".encode())
    return xof.read


#
# Serialization tests
#


@pytest.mark.parametrize("n", ALL_MODULI)
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


@pytest.mark.parametrize("n", ALL_MODULI)
def test_serialize_deserialize_vec_roundtrip(n):
    kem = KOPIS_768
    vec = kopis.make_vecn(
        n,
        [
            make_rn(n, [(i * 7 + j) % (1 << n) for j in range(256)])
            for i in range(kem.ell)
        ],
    )
    data = kem.serialize_vec(n, vec)
    assert len(data) == kem.ell * 256 * n // 8
    assert kem.deserialize_vec(n, data) == vec


# n-bit deserialization must never yield a value >= 2^n
@pytest.mark.parametrize("n", ALL_MODULI)
def test_deserialize_masks_to_n_bits(n):
    data = bytes([0xFF]) * (256 * n // 8)
    coeffs = canonical_coeffs(deserialize_elem(n, data))
    assert all(c == (1 << n) - 1 for c in coeffs)


#
# Arithmetic tests
#


# X^255 * X = X^256 = -1 in Rn
@pytest.mark.parametrize("n", ALL_MODULI)
def test_mul_is_negacyclic(n):
    a = [0] * 256
    a[255] = 1
    b = [0] * 256
    b[1] = 1
    expected = [0] * 256
    expected[0] = (-1) % (1 << n)
    assert make_rn(n, a) * make_rn(n, b) == make_rn(n, expected)


@pytest.mark.parametrize("n", ALL_MODULI)
def test_mul_identity(n):
    one = [0] * 256
    one[0] = 1
    a = make_rn(n, [(i * 3 + 1) % (1 << n) for i in range(256)])
    assert a * make_rn(n, one) == a


#
# Correctness tests
#

# Number of iterations for correctness tests
CORRECTNESS_N_ITERS = 5


# Check decap is the inverse of encap
@pytest.mark.parametrize("kem", ALL_LEVELS)
def test_roundtrip_random(kem, rng):
    for _ in range(CORRECTNESS_N_ITERS):
        sk = rng(32)
        pk = kem.SkToPk(sk)
        for _ in range(10):
            ss, ct = kem.KemEncap(rng(32), pk)
            assert kem.KemDecap(sk, ct) == ss

        # Now do unusual secret keys
        for sk in (bytes(32), bytes([0xFF] * 32), bytes(range(32))):
            pk = kem.SkToPk(sk)
            ss, ct = kem.KemEncap(rng(32), pk)
            assert kem.KemDecap(sk, ct) == ss


# Check decrypt is the inverse of encrypt
@pytest.mark.parametrize("kem", ALL_LEVELS)
def test_pke_roundtrip(kem, rng):
    for _ in range(CORRECTNESS_N_ITERS):
        sk = rng(32)
        pk = kem.SkToPk(sk)
        msg = rng(32)
        ct = kem.PkeEncrypt(rng(32), pk, msg)
        assert kem.PkeDecrypt(sk, ct) == msg


# Check the Fujisaki-Okamoto transform is implemented
@pytest.mark.parametrize("kem", ALL_LEVELS)
def test_implicit_rejection(kem, rng):
    for _ in range(CORRECTNESS_N_ITERS):
        sk = rng(32)
        pk = kem.SkToPk(sk)
        ss, ct = kem.KemEncap(rng(32), pk)

        mauled = bytearray(ct)
        mauled[0] ^= 0x01
        mauled = bytes(mauled)

        # Mauling should affect the shared secret
        dss = kem.KemDecap(sk, mauled)
        assert dss != ss

        # The rejection value is TurboSHAKE256(z || ct, 32, DOMSEP_NOREJECT)
        _, z, _, _ = kem.ExpandSecretKey(sk)
        assert dss == TurboSHAKE256(z + mauled, 32, DOMSEP_NOREJECT)


#
# Well-formedness tests
#


@pytest.mark.parametrize("kem", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [0, 31, 33, 64])
def test_wrong_length_sk_rejected(kem, bad_len, rng):
    sk = rng(bad_len)
    with pytest.raises(InvalidInput):
        kem.SkToPk(sk)
    with pytest.raises(InvalidInput):
        kem.KemDecap(sk, bytes(kem.CT_SIZE))


@pytest.mark.parametrize("kem", ALL_LEVELS)
@pytest.mark.parametrize("delta", [-1, 1])
def test_wrong_length_pk_rejected(kem, delta, rng):
    pk = rng(kem.PK_SIZE + delta)
    with pytest.raises(InvalidInput):
        kem.KemEncap(rng(32), pk)
    with pytest.raises(InvalidInput):
        kem.PkeEncrypt(rng(32), pk, rng(32))


@pytest.mark.parametrize("kem", ALL_LEVELS)
@pytest.mark.parametrize("delta", [-1, 1])
def test_wrong_length_ct_rejected(kem, delta, rng):
    sk = rng(32)
    ct = rng(kem.CT_SIZE + delta)
    with pytest.raises(InvalidInput):
        kem.KemDecap(sk, ct)
    with pytest.raises(InvalidInput):
        kem.PkeDecrypt(sk, ct)


@pytest.mark.parametrize("kem", ALL_LEVELS)
def test_empty_ct_rejected(kem, rng):
    with pytest.raises(InvalidInput):
        kem.KemDecap(rng(32), b"")


@pytest.mark.parametrize("kem", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [31, 33, 48])
def test_wrong_length_encap_randomness_rejected(kem, bad_len, rng):
    pk = kem.SkToPk(rng(32))
    with pytest.raises(InvalidInput):
        kem.KemEncap(rng(bad_len), pk)


@pytest.mark.parametrize("kem", ALL_LEVELS)
@pytest.mark.parametrize("bad_len", [31, 33])
def test_wrong_length_pke_msg_rejected(kem, bad_len, rng):
    pk = kem.SkToPk(rng(32))
    with pytest.raises(InvalidInput):
        kem.PkeEncrypt(rng(32), pk, rng(bad_len))


@pytest.mark.parametrize("kem", ALL_LEVELS)
def test_pk_for_another_parameter_set_rejected(kem, rng):
    sk = rng(32)
    for other in ALL_LEVELS:
        if other is kem:
            continue
        with pytest.raises(InvalidInput):
            kem.KemEncap(rng(32), other.SkToPk(sk))


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


#
# Known-answer tests
#


# Check that the test vectors produced in `gen_test_vectors.py`, if present, pass
@pytest.mark.parametrize("level", [512, 768, 1024])
def test_generated_vectors_consistent(level):
    path = os.path.join(HERE, f"test_vectors-kopis{level}.jsonl")
    if not os.path.exists(path):
        pytest.skip(f"{path} not generated; run gen_test_vectors.py first")

    kem = PARAMS[level]
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
                    kem.SkToPk(sk)
            if len(encap_randomness) != 32 or len(pk) != kem.PK_SIZE:
                with pytest.raises(InvalidInput):
                    kem.KemEncap(encap_randomness, pk)
            if len(sk) != kopis.SK_SIZE or len(decapper_ct) != kem.CT_SIZE:
                with pytest.raises(InvalidInput):
                    kem.KemDecap(sk, decapper_ct)
        else:
            # Well-formed vector: the implementation must reproduce it exactly.
            assert len(sk) == kopis.SK_SIZE
            assert kem.SkToPk(sk) == pk
            assert len(encap_randomness) == 32

            ss, ct = kem.KemEncap(encap_randomness, pk)
            assert ss == encapper_ss
            assert ct == encapper_ct

            assert kem.KemDecap(sk, decapper_ct) == decapper_ss

            if decapper_ct == encapper_ct:
                # Honest vector: encapper and decapper shared secrets agree.
                assert decapper_ss == encapper_ss
            else:
                # Mauled vector: the decapper obtains a different shared secret.
                assert decapper_ss != encapper_ss


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_generated_vectors_have_all_categories(level):
    path = os.path.join(HERE, f"test_vectors_kopis{level}.jsonl")
    if not os.path.exists(path):
        pytest.skip(f"{path} not generated; run gen_test_vectors.py first")

    with open(path) as f:
        vectors = [json.loads(line) for line in f if line.strip()]

    descriptions = [v["description"] for v in vectors]
    assert any(d.startswith("honest") for d in descriptions)
    assert any(d.startswith("mauled") for d in descriptions)
    assert any(v["malformed"] for v in vectors)
    # Malformed vectors carry a coerced-computation result, not an empty field.
    assert all(v["encapper_ss"] and v["decapper_ss"] for v in vectors if v["malformed"])
