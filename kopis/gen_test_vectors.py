"""Reproducible Kopis KEM test-vector generator.

Running this script writes three files next to it:

    test_vectors-kopis512.jsonl
    test_vectors-kopis768.jsonl
    test_vectors-kopis1024.jsonl

Each line is a JSON object with the following (hex-encoded) fields:

    description       text describing what the vector tests
    sk                the KEM secret key
    pk                serialized KEM public key corresponding to ``sk``
    encap_randomness  randomness used to encapsulate to ``pk``
    encapper_ct       serialized KEM ciphertext produced by encapsulation
    decapper_ct       a KEM ciphertext (may or may not equal encapper_ct)
    encapper_ss       shared secret from the encapsulation that built encapper_ct
    decapper_ss       shared secret from decapsulating decapper_ct with sk
    malformed         bool: whether some value is malformed (invalid test)

A vector with ``malformed`` set has at least one value whose length is wrong
for the parameter set, and a conforming implementation MUST reject it. Its
output fields are still populated: they hold what an implementation that
silently coerced the bad value to the expected length -- zero-padding what is
too short, truncating what is too long -- would compute. Reproducing any of
them therefore identifies that specific bug.

All randomness used by this generator is derived deterministically from a
single seeded TurboSHAKE128 instance, so the output is fully reproducible.
"""

from __future__ import annotations

import json
import os

from xoflib import turbo_shake128

import kopis

# ---------------------------------------------------------------------------
# Deterministic randomness: one seeded TurboSHAKE128 sponge drives everything.
# ---------------------------------------------------------------------------

_RNG = turbo_shake128(0x1F, b"kopis-kem test vector generator :: seed v1")


def rand(n: int) -> bytes:
    """Return the next ``n`` bytes from the seeded generator."""
    return _RNG.read(n)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Global counter to number vectors as we make them
vectors_generated = 0

# Constructor for test vectors
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
    """Build a test-vector dict, hex-encoding every byte string field."""
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


# ---------------------------------------------------------------------------
# Good vectors: everything computed honestly
# ---------------------------------------------------------------------------


def good_vector(k, sk, description):
    pk = k.SkToPk(sk)
    encap_randomness = rand(32)
    ss, ct = k.KemEncap(encap_randomness, pk)
    dss = k.KemDecap(sk, ct)
    assert dss == ss, "honest round-trip must agree"
    return vector(description, sk, pk, encap_randomness, ct, ct, ss, dss, False)


# ---------------------------------------------------------------------------
# Mauled-ciphertext vectors: decapper ct differs; still correct length.
# ---------------------------------------------------------------------------


def mauled_vector(k, sk, description, maul):
    pk = k.SkToPk(sk)
    encap_randomness = rand(32)
    ss, ct = k.KemEncap(encap_randomness, pk)
    mauled = maul(bytearray(ct))
    assert len(mauled) == k.CT_SIZE, "maul must preserve length"
    assert mauled != ct, "maul must actually change the ciphertext"
    dss = k.KemDecap(sk, mauled)
    # Implicit rejection means the decapper derives a different shared secret.
    assert dss != ss, "mauled ciphertext must yield a different shared secret"
    return vector(description, sk, pk, encap_randomness, ct, mauled, ss, dss, False)


def _flip_first_bit(buf):
    buf[0] ^= 0x01
    return bytes(buf)


def _flip_last_bit(buf):
    buf[-1] ^= 0x80
    return bytes(buf)


def _flip_middle_bit(buf):
    buf[len(buf) // 2] ^= 0x08
    return bytes(buf)


def _reverse(buf):
    return bytes(reversed(buf))


def _zero_out(buf):
    return bytes(len(buf))


def _all_ones(buf):
    return bytes([0xFF] * len(buf))


# ---------------------------------------------------------------------------
# Malformed vectors: at least one recorded value has the wrong length, so a
# conforming implementation MUST reject the vector outright.
#
# The recorded outputs are not empty, though. They are what a NON-conforming
# implementation would produce if it silently coerced the bad value to the
# expected length -- zero-padding what is too short, truncating what is too
# long -- and then carried on as normal. An implementation that reproduces any
# of these outputs has exactly that bug.
# ---------------------------------------------------------------------------


def coerce(value, size):
    """Zero-pad or truncate ``value`` to ``size`` bytes, as a sloppy impl would."""
    return value[:size] + bytes(max(0, size - len(value)))


def malformed_vectors(k, level):
    """Yield a series of malformed vectors for parameter set ``k``."""
    other_level = {512: 1024, 768: 512, 1024: 768}[level]
    other = kopis.PARAMS[other_level]

    base_sk = rand(32)
    base_pk = k.SkToPk(base_sk)
    base_rand = rand(32)
    base_ss, base_ct = k.KemEncap(base_rand, base_pk)

    # 1. secret key too short (31 bytes) -> zero-padded to 32
    bad_sk = rand(31)
    sk = coerce(bad_sk, kopis.SK_SIZE)
    pk = k.SkToPk(sk)
    r = rand(32)
    ss, ct = k.KemEncap(r, pk)
    dss = k.KemDecap(sk, ct)
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

    # 2. secret key too long (33 bytes) -> truncated to 32
    bad_sk = rand(33)
    sk = coerce(bad_sk, kopis.SK_SIZE)
    pk = k.SkToPk(sk)
    r = rand(32)
    ss, ct = k.KemEncap(r, pk)
    dss = k.KemDecap(sk, ct)
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

    # 3. encapsulation randomness too short (31 bytes) -> zero-padded to 32
    bad_rand = rand(31)
    ss, ct = k.KemEncap(coerce(bad_rand, 32), base_pk)
    dss = k.KemDecap(base_sk, ct)
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

    # 4. encapsulation randomness too long (48 bytes) -> truncated to 32
    bad_rand = rand(48)
    ss, ct = k.KemEncap(coerce(bad_rand, 32), base_pk)
    dss = k.KemDecap(base_sk, ct)
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

    # 5. public key truncated by one byte -> zero-padded back to PK_SIZE.
    # Padding restores the length but (almost surely) not the last mat_seed
    # byte, so the honest decapper implicitly rejects the resulting ct.
    bad_pk = base_pk[:-1]
    r = rand(32)
    ss, ct = k.KemEncap(r, coerce(bad_pk, k.PK_SIZE))
    dss = k.KemDecap(base_sk, ct)
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

    # 6. public key sized for a different parameter set -> coerced to PK_SIZE
    bad_pk = other.SkToPk(base_sk)
    r = rand(32)
    ss, ct = k.KemEncap(r, coerce(bad_pk, k.PK_SIZE))
    dss = k.KemDecap(base_sk, ct)
    fix = "truncated" if len(bad_pk) > k.PK_SIZE else "zero-padded"
    yield vector(
        f"malformed: public key is {other.PK_SIZE} bytes "
        f"(sized for {other.name}, expected {k.PK_SIZE} for {k.name}); "
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

    # 7. decapper ciphertext truncated by one byte -> zero-padded to CT_SIZE
    bad_ct = base_ct[:-1]
    dss = k.KemDecap(base_sk, coerce(bad_ct, k.CT_SIZE))
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

    # 8. decapper ciphertext with a trailing extra byte -> truncated to
    # CT_SIZE
    bad_ct = base_ct + b"\x00"
    dss = k.KemDecap(base_sk, coerce(bad_ct, k.CT_SIZE))
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

    # 9. ciphertext sized for a different parameter set -> coerced back to CT_SIZE
    r = rand(32)
    ss, bad_ct = other.KemEncap(r, coerce(base_pk, other.PK_SIZE))
    dss = k.KemDecap(base_sk, coerce(bad_ct, k.CT_SIZE))
    yield vector(
        f"malformed: ciphertext is {other.CT_SIZE} bytes "
        f"(sized for {other.name}, expected {k.CT_SIZE} for {k.name}); "
        f"encapper coerced pk to {other.name} and encapped there; "
        f"decapper_ss is for the ciphertext coerced back to {k.name}",
        base_sk,
        base_pk,
        r,
        bad_ct,
        bad_ct,
        ss,
        dss,
        True,
    )

    # 10. empty decapper ciphertext -> zero-padded to CT_SIZE
    dss = k.KemDecap(base_sk, coerce(b"", k.CT_SIZE))
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

    # 11. public key and ciphertext both sized for a different parameter set:
    # a wholly honest vector, just at the wrong level
    wrong_pk = other.SkToPk(base_sk)
    ss, ct = other.KemEncap(base_rand, wrong_pk)
    dss = other.KemDecap(base_sk, ct)
    yield vector(
        f"malformed: public key and ciphertext are both sized for "
        f"{other.name} (expected {k.name}); an honest {other.name} vector",
        base_sk,
        wrong_pk,
        base_rand,
        ct,
        ct,
        ss,
        dss,
        True,
    )


# ---------------------------------------------------------------------------
# Assemble all vectors for one parameter set.
# ---------------------------------------------------------------------------


def vectors_for_level(level):
    k = kopis.PARAMS[level]
    out = []

    # -- good vectors -----------------------------------------------------
    # A handful of random secret keys.
    for i in range(4):
        out.append(good_vector(k, rand(32), f"good: random secret key #{i + 1}"))

    # All-zero secret key.
    out.append(good_vector(k, bytes(32), "good: all-zero secret key"))
    # All-ones secret key.
    out.append(good_vector(k, bytes([0xFF] * 32), "good: all-0xff secret key"))
    # A structured secret key (0x00, 0x01, ... 0x1f).
    out.append(
        good_vector(k, bytes(range(32)), "good: structured secret key (0x00..0x1f)")
    )
    # Single non-zero byte.
    out.append(
        good_vector(
            k, bytes([0x01]) + bytes(31), "good: secret key with a single set byte"
        )
    )

    # -- mauled ciphertext vectors ---------------------------------------
    mauls = [
        (_flip_first_bit, "mauled: first bit of ciphertext flipped"),
        (_flip_last_bit, "mauled: high bit of last ciphertext byte flipped"),
        (_flip_middle_bit, "mauled: a bit in the middle of the ciphertext flipped"),
        (_reverse, "mauled: ciphertext byte order reversed"),
        (_zero_out, "mauled: ciphertext replaced by all zeros"),
        (_all_ones, "mauled: ciphertext replaced by all 0xff bytes"),
    ]
    for maul, desc in mauls:
        out.append(mauled_vector(k, rand(32), desc, maul))

    # -- malformed vectors ------------------------------------------------
    out.extend(malformed_vectors(k, level))

    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for level in (512, 768, 1024):
        vectors = vectors_for_level(level)
        path = os.path.join(here, f"test_vectors-kopis{level}.jsonl")
        with open(path, "w") as f:
            for v in vectors:
                f.write(json.dumps(v) + "\n")
        n_good = sum(1 for v in vectors if v["description"].startswith("good"))
        n_maul = sum(1 for v in vectors if v["description"].startswith("mauled"))
        n_bad = sum(1 for v in vectors if v["malformed"])
        print(
            f"kopis{level}: wrote {len(vectors)} vectors "
            f"({n_good} good, {n_maul} mauled, {n_bad} malformed) -> {path}"
        )


if __name__ == "__main__":
    main()
