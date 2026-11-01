import json
import os

from xoflib import turbo_shake128

import kopis

# Deterministic global RNG used for all test vectors
_RNG = turbo_shake128(0x1F, b"kopis-test-vectors-seed1")


def randombytes(n: int) -> bytes:
    """Return the next ``n`` bytes from the global RNG."""
    return _RNG.read(n)


#
# Helper functions
#

# Global counter to number vectors as we make them
vectors_generated = 0


def vector(
    description,
    sk,
    pk,
    encap_randomness,
    encapper_ct,
    decapper_ct,
    encapper_ss,
    decapper_ss,
    malformed,
):
    """Build a test vector with the given fields"""
    global vectors_generated
    vectors_generated += 1
    return {
        "description": description,
        "number": vectors_generated,
        "sk": sk.hex(),
        "pk": pk.hex(),
        "encap_randomness": encap_randomness.hex(),
        "encapper_ct": encapper_ct.hex(),
        "decapper_ct": decapper_ct.hex(),
        "encapper_ss": encapper_ss.hex(),
        "decapper_ss": decapper_ss.hex(),
        "malformed": malformed,
    }


def honest_vector(kem, sk, description):
    """Generate an honest test vector (no tampering) with the given secret key"""
    pk = kem.SkToPk(sk)
    encap_randomness = randombytes(32)
    ss, ct = kem.KemEncap(encap_randomness, pk)
    dss = kem.KemDecap(sk, ct)
    assert dss == ss, "honest round-trip must agree"
    return vector(description, sk, pk, encap_randomness, ct, ct, ss, dss, False)


def mauled_vector(kem, sk, description, maulf):
    """Generate a mauled-ciphertext test vector with the given sk and mauling function"""
    pk = kem.SkToPk(sk)
    encap_randomness = randombytes(32)
    ss, ct = kem.KemEncap(encap_randomness, pk)
    mauled_ct = maulf(bytearray(ct))
    assert len(mauled_ct) == kem.CT_SIZE, "maul must preserve length"
    assert mauled_ct != ct, "maul must actually change the ciphertext"
    dss = kem.KemDecap(sk, mauled_ct)
    # Implicit rejection means the decapper derives a different shared secret.
    assert dss != ss, "mauled ciphertext must yield a different shared secret"
    return vector(description, sk, pk, encap_randomness, ct, mauled_ct, ss, dss, False)


#
# Malformed vectors
#


def coerce(value, size):
    """Zero-pad or truncate ``value`` to ``size`` bytes"""
    return value[:size] + bytes(max(0, size - len(value)))


def malformed_vectors(kem, level):
    """Generate a series of malformed vectors for ``kem``."""
    # We will try to guess what a sloppy impl would do. As part of this, we will choose sizes that
    # are invalid for the target security level, but valid for a different one
    other_level = {512: 1024, 768: 512, 1024: 768}[level]
    other = kopis.PARAMS[other_level]

    base_sk = randombytes(32)
    base_pk = kem.SkToPk(base_sk)
    base_rand = randombytes(32)
    base_ss, base_ct = kem.KemEncap(base_rand, base_pk)

    # 1. Make sk too short. A bad impl might zero-pad this, so that's what we do
    bad_sk = randombytes(31)
    sk = coerce(bad_sk, kopis.SK_SIZE)
    pk = kem.SkToPk(sk)
    r = randombytes(32)
    ss, ct = kem.KemEncap(r, pk)
    dss = kem.KemDecap(sk, ct)
    yield vector(
        "malformed: secret key is 31 bytes (must be 32); "
        "outputs are for the zero-padded key",
        bad_sk,
        pk,
        r,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 2. Make sk too long. A bad impl might truncate to 32
    bad_sk = randombytes(33)
    sk = coerce(bad_sk, kopis.SK_SIZE)
    pk = kem.SkToPk(sk)
    r = randombytes(32)
    ss, ct = kem.KemEncap(r, pk)
    dss = kem.KemDecap(sk, ct)
    yield vector(
        "malformed: secret key is 33 bytes (must be 32); "
        "outputs are for the truncated key",
        bad_sk,
        pk,
        r,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 3. Make the encap randomness too short. A bad impl might zero-pad to 32
    bad_rand = randombytes(31)
    ss, ct = kem.KemEncap(coerce(bad_rand, 32), base_pk)
    dss = kem.KemDecap(base_sk, ct)
    yield vector(
        "malformed: encapsulation randomness is 31 bytes (must be 32); "
        "outputs are for the zero-padded randomness",
        base_sk,
        base_pk,
        bad_rand,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 4. Make encap randomness too long. A bad impl might truncate to 32
    bad_rand = randombytes(48)
    ss, ct = kem.KemEncap(coerce(bad_rand, 32), base_pk)
    dss = kem.KemDecap(base_sk, ct)
    yield vector(
        "malformed: encapsulation randomness is 48 bytes (must be 32); "
        "outputs are for the truncated randomness",
        base_sk,
        base_pk,
        bad_rand,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 5. Make pk too short. A bad impl might zero-pad to PK_SIZE.
    bad_pk = base_pk[:-1]
    r = randombytes(32)
    ss, ct = kem.KemEncap(r, coerce(bad_pk, kem.PK_SIZE))
    dss = kem.KemDecap(base_sk, ct)
    yield vector(
        "malformed: public key truncated by one byte; "
        "outputs are for the zero-padded key",
        base_sk,
        bad_pk,
        r,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 6. Make a public key whose size matches a different parameter set. A bad impl might
    # truncate/pad to PK_SIZE of whichever parameter set matched
    bad_pk = other.SkToPk(base_sk)
    r = randombytes(32)
    ss, ct = kem.KemEncap(r, coerce(bad_pk, kem.PK_SIZE))
    dss = kem.KemDecap(base_sk, ct)
    fix = "truncated" if len(bad_pk) > kem.PK_SIZE else "zero-padded"
    yield vector(
        f"malformed: public key is {other.PK_SIZE} bytes "
        f"(sized for {other.name}, expected {kem.PK_SIZE} for {kem.name}); "
        f"outputs are for the {fix} key",
        base_sk,
        bad_pk,
        r,
        ct,
        ct,
        ss,
        dss,
        True,
    )

    # 7. Make decapper_ct too small. A bad impl might zero-pad to CT_SIZE
    bad_ct = base_ct[:-1]
    dss = kem.KemDecap(base_sk, coerce(bad_ct, kem.CT_SIZE))
    yield vector(
        "malformed: decapper ciphertext truncated by one byte; "
        "decapper_ss is for the zero-padded ciphertext",
        base_sk,
        base_pk,
        base_rand,
        base_ct,
        bad_ct,
        base_ss,
        dss,
        True,
    )

    # 8. Make decapper_ct too big. A bad impl might truncate to CT_SIZE
    bad_ct = base_ct + b"\x00"
    dss = kem.KemDecap(base_sk, coerce(bad_ct, kem.CT_SIZE))
    yield vector(
        "malformed: decapper ciphertext has one extra trailing byte; "
        "decapper_ss is for the truncated ciphertext",
        base_sk,
        base_pk,
        base_rand,
        base_ct,
        bad_ct,
        base_ss,
        dss,
        True,
    )

    # 9. Size both cipehrtexts for a different parameter set. A bad impl would truncate/pad to the
    # CT_SIZE of the matching parameter set.
    r = randombytes(32)
    ss, bad_ct = other.KemEncap(r, coerce(base_pk, other.PK_SIZE))
    dss = kem.KemDecap(base_sk, coerce(bad_ct, kem.CT_SIZE))
    yield vector(
        f"malformed: ciphertext is {other.CT_SIZE} bytes "
        f"(sized for {other.name}, expected {kem.CT_SIZE} for {kem.name}); "
        f"encapper coerced pk to {other.name} and encapped there; "
        f"decapper_ss is for the ciphertext coerced back to {kem.name}",
        base_sk,
        base_pk,
        r,
        bad_ct,
        bad_ct,
        ss,
        dss,
        True,
    )

    # 10. Make decapper_ct empty. A bad impl might pad to CT_SIZE.
    dss = kem.KemDecap(base_sk, coerce(b"", kem.CT_SIZE))
    yield vector(
        "malformed: decapper ciphertext is empty; "
        "decapper_ss is for the all-zero ciphertext",
        base_sk,
        base_pk,
        base_rand,
        base_ct,
        b"",
        base_ss,
        dss,
        True,
    )

    # 11. Size pk and ciphertexts for a different parameter set. This is an honest vector, just at
    # the wrong security level.
    wrong_pk = other.SkToPk(base_sk)
    ss, ct = other.KemEncap(base_rand, wrong_pk)
    dss = other.KemDecap(base_sk, ct)
    yield vector(
        f"malformed: public key and ciphertext are both sized for "
        f"{other.name} (expected {kem.name}); an honest {other.name} vector",
        base_sk,
        wrong_pk,
        base_rand,
        ct,
        ct,
        ss,
        dss,
        True,
    )


#
# Now assemble the test vectors
#


# XOR the given mask into buf[idx]. This is used for mauling
def xor_at(buf, idx, mask):
    buf[idx] ^= mask
    return bytes(buf)


# Produce a list of test vectors for the given level (1, 3, or 5)
def vectors_for_level(level):
    kem = kopis.PARAMS[level]
    out = []

    # Generate 4 random honest vectors
    for i in range(4):
        out.append(
            honest_vector(kem, randombytes(32), f"honest: random secret key #{i + 1}")
        )
    # Make a vector with the all-zero secret key
    out.append(honest_vector(kem, bytes(32), "honest: all-zero secret key"))
    # Make a vector with the all-one secret key
    out.append(honest_vector(kem, bytes([0xFF] * 32), "honest: all-0xff secret key"))
    # Make a vector with a structured secret key (0x00, 0x01, ... 0x1f).
    out.append(
        honest_vector(
            kem, bytes(range(32)), "honest: structured secret key (0x00..0x1f)"
        )
    )
    # Make a vector with a single non-zero byte
    out.append(
        honest_vector(
            kem, bytes([0x01]) + bytes(31), "honest: secret key with a single set byte"
        )
    )

    # Now generate mauled vectors
    mauls = [
        (lambda buf: xor_at(buf, 0, 0x01), "mauled: first bit of ciphertext flipped"),
        (
            lambda buf: xor_at(buf, -1, 0x80),
            "mauled: high bit of last ciphertext byte flipped",
        ),
        (
            lambda buf: xor_at(buf, len(buf) // 2, 0x08),
            "mauled: a bit in the middle of the ciphertext flipped",
        ),
        (lambda buf: bytes(reversed(buf)), "mauled: ciphertext byte order reversed"),
        (lambda buf: bytes(len(buf)), "mauled: ciphertext replaced by all zeros"),
        (
            lambda buf: bytes([0xFF] * len(buf)),
            "mauled: ciphertext replaced by all 0xff bytes",
        ),
    ]
    for maul, desc in mauls:
        out.append(mauled_vector(kem, randombytes(32), desc, maul))

    # Now generate malformed vectosr
    out.extend(malformed_vectors(kem, level))

    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for level in (512, 768, 1024):
        vectors = vectors_for_level(level)
        path = os.path.join(here, f"test_vectors-kopis{level}.jsonl")
        with open(path, "w") as f:
            f.writelines(json.dumps(v) + "\n" for v in vectors)
        n_honest = sum(1 for v in vectors if v["description"].startswith("honest"))
        n_maul = sum(1 for v in vectors if v["description"].startswith("mauled"))
        n_bad = sum(1 for v in vectors if v["malformed"])
        print(
            f"kopis{level}: wrote {len(vectors)} vectors "
            f"({n_honest} honest, {n_maul} mauled, {n_bad} malformed) -> {path}"
        )


if __name__ == "__main__":
    main()
