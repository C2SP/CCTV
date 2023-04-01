#! /usr/bin/env python3

# This script uses the jq255 implementation (jq255.py) to generate test
# vectors. One command-line argument:
#    jq255e    make test vectors for jq255e
#    jq255s    make test vectors for jq255s
# If no argument is provided, then 'jq255e' is assumed.
#
# Test vectors are produced on standard output. Test vector production
# is deterministic (you always get the same vectors for a given curve).

import importlib
import sys
import hashlib
import json
import jq255

def add_test(tl, testtype, vv):
    vv['id'] = '%s%d' % (testtype, len(tl))
    tl.append(vv)

# Make test vectors for decoding tests.
def mktests_decode(curve):
    tl = []

    # The all-zero input is decodable.
    add_test(tl, 'decode', { "data": "0000000000000000000000000000000000000000000000000000000000000000", "decodable": True })

    # Make some pseudorandom decodable inputs.
    rs = hashlib.sha256(curve.bname + b'-test-decode').digest()
    ap = -2*curve.a
    bp = curve.a**2 - 4*curve.b
    for i in range(0, 20):
        while True:
            rs = hashlib.sha256(rs).digest()
            rt = int.from_bytes(rs, byteorder='big')
            u = curve.K(rt)
            if (bp*u**4 + ap*u**2 + 1).is_square():
                break
        val = bytes(u)
        # Try decoding, it should work.
        P = curve.Decode(val)
        val2 = bytes(P)
        if val != val2:
            raise Exception('Decode/encode failed (different bytes)')
        add_test(tl, 'decode', { "data": val.hex(), "decodable": True })

    # Make some non-decodable inputs because u is out of range.
    for i in range(0, 20):
        if i == 0:
            # First test checks that values just above the modulus are
            # properly rejected, instead of being implicitly reduced.
            iu = curve.K.m + 1
            while True:
                u = curve.K(iu)
                if (bp*u**4 + ap*u**2 + 1).is_square():
                    break
                iu += 1
        else:
            # Even-numbered tests verify that the top bit is checked but
            # not ignored; odd-numbered tests verify that the whole value
            # is not implicitly reduced.
            while True:
                rs = hashlib.sha256(rs).digest()
                iu = int.from_bytes(rs, byteorder='big')
                if (i & 1) == 0:
                    if iu < 2**255:
                        u = curve.K(iu)
                        iu += 2**255
                    else:
                        u = curve.K(iu - 2**255)
                else:
                    if iu < 2**255:
                        iu += 2**255
                    u = curve.K(iu)
                if (bp*u**4 + ap*u**2 + 1).is_square():
                    break
        val = iu.to_bytes(32, byteorder='little')
        # Try decoding, it should fail.
        good = False
        try:
            curve.Decode(val)
        except Exception:
            good = True
        if not good:
            raise Exception('Decoding should have failed')
        add_test(tl, 'decode', { "data": val.hex(), "decodable": False })

    # Make some non-decodable inputs (u is in range, but matches no point).
    for i in range(0, 20):
        while True:
            rs = hashlib.sha256(rs).digest()
            rt = int.from_bytes(rs, byteorder='big')
            u = curve.K(rt)
            if not((bp*u**4 + ap*u**2 + 1).is_square()):
                break
        val = bytes(u)
        # Try decoding, it should fail.
        good = False
        try:
            curve.Decode(val)
        except Exception:
            good = True
        if not good:
            raise Exception('Decoding should have failed')
        add_test(tl, 'decode', { "data": val.hex(), "decodable": False })

    return tl

# Make test vectors for map-to-curve tests.
def mktests_map(curve):
    tl = []
    rs = hashlib.sha256(curve.bname + b'-test-map').digest()
    for i in range(0, 40):
        rs = hashlib.sha256(rs).digest()
        if i == 0:
            bb = bytearray(32)
            if not curve.a.is_zero():
                bb[0] = 1
        else:
            bb = rs
        P = curve.MapToCurve(bb)
        if i == 0:
            if not P.is_neutral():
                raise Exception('zero should be mapped to neutral')
        else:
            # Sanity checks on the point.
            if P.Z.is_zero():
                raise Exception('invalid point')
            e = P.E / P.Z
            u = P.U / P.Z
            if P.U**2 != P.T*P.Z:
                raise Exception('invalid point')
            if e**2 != curve.bp*u**4 + curve.ap*u**2 + curve.K.one:
                raise Exception('invalid point')
            x = (e + curve.K.one - curve.a*u**2) / (2*u**2)
            w = curve.K.one / u
            if w**2*x != x**2 + curve.a*x + curve.b:
                raise Exception('invalid point')
            if x.is_square():
                raise Exception('mapped to an r-torsion point')
        add_test(tl, 'map', { "f": bb.hex(), "p": bytes(P).hex() })

    return tl

# Make test vectors for point addition.
def mktests_add(curve):
    tl = []
    rs = hashlib.sha256(curve.bname + b'-test-add').digest()
    for i in range(0, 20):
        rs = hashlib.sha256(rs).digest()
        rt = int.from_bytes(rs, byteorder='big')
        P1 = curve.G * rt
        rs = hashlib.sha256(rs).digest()
        rt = int.from_bytes(rs, byteorder='big')
        P2 = curve.G * rt
        P3 = P1 + P2
        P4 = P1 + P1
        P5 = P4 + P2
        P6 = P3 + P3
        add_test(tl, 'add', { "p1": bytes(P1).hex(), "p2": bytes(P2).hex(), "p3": bytes(P3).hex(), "p4": bytes(P4).hex(), "p5": bytes(P5).hex(), "p6": bytes(P6).hex() })

    return tl

# Make test vectors for point multiplication.
# Scalars may range up to the full 256-bit range.
def mktests_mul(curve):
    tl = []
    rs = hashlib.sha256(curve.bname + b'-test-pointmul').digest()
    for i in range(0, 20):
        rs = hashlib.sha256(rs).digest()
        rt = int.from_bytes(rs, byteorder='big')
        P1 = curve.G * rt
        rs = hashlib.sha256(rs).digest()
        rt = curve.SF(int.from_bytes(rs, byteorder='big'))
        P3 = P1 * rt
        add_test(tl, 'mul', { "p": bytes(P1).hex(), "q": bytes(P3).hex(), "s": bytes(rt).hex() })

    return tl

def mktests_keygen(curve):
    tl = []
    for i in range(0, 20):
        sh = hashlib.shake_256()
        sh.update(int(i).to_bytes(1, 'little'))
        sk = jq255.Keygen(curve, sh)
        pk = jq255.MakePublic(curve, sk)
        add_test(tl, 'keygen', { "sk": bytes(sk).hex(), "pk": bytes(pk).hex() })
    return tl

def mktests_hashraw(curve):
    tl = []
    data = bytearray()
    for i in range(0, 100):
        P = jq255.HashToCurve(curve, b'', data)
        add_test(tl, 'hashraw', { "raw": data.hex(), "p": bytes(P).hex() })
        data.append(i)
    return tl

def mktests_hashph(curve):
    tl = []
    data = bytearray()
    for i in range(0, 10):
        sh = hashlib.blake2s()
        sh.update(i.to_bytes(1, byteorder='little'))
        data = sh.digest()
        P = jq255.HashToCurve(curve, jq255.HASHNAME_BLAKE2S, data)
        add_test(tl, 'hashph', { "hv": data.hex(), "p": bytes(P).hex() })
    return tl

def mktests_ECDH(curve):
    tl = []
    for i in range(0, 20):
        # Valid test.
        rng = hashlib.shake_256()
        rng.update(curve.bname)
        rng.update(b'-test-ECDH-self-')
        rng.update(int(i).to_bytes(2, 'little'))
        sk_self = jq255.Keygen(curve, rng)
        pk_self = jq255.MakePublic(curve, sk_self)
        rng = hashlib.shake_256()
        rng.update(curve.bname)
        rng.update(b'-test-ECDH-peer-')
        rng.update(int(i).to_bytes(2, 'little'))
        sk_peer = jq255.Keygen(curve, rng)
        pk_peer = jq255.MakePublic(curve, sk_peer)
        secret, ok = jq255.ECDH(sk_self, pk_self, pk_peer)
        if not ok:
            raise Exception('ECDH failed')
        # Try again with decoding inside the function.
        secret2, ok2 = jq255.ECDH(sk_self, pk_self, bytes(pk_peer))
        if not ok2:
            raise Exception('ECDH failed (with decoding)')
        if secret2 != secret:
            raise Exception('ECDH wrong secret (with decoding)')
        # Verify that the peer would get the same value.
        secret3, ok3 = jq255.ECDH(sk_peer, pk_peer, pk_self)
        if not ok3:
            raise Exception('ECDH failed (reverse)')
        if secret3 != secret:
            raise Exception('ECDH wrong secret (reverse)')

        # Invalid test.
        j = 0
        while True:
            rng = hashlib.shake_256()
            rng.update(curve.bname)
            rng.update(b'-test-ECDH-peer-')
            rng.update(int(i).to_bytes(2, 'little'))
            rng.update(int(j).to_bytes(4, 'little'))
            u = curve.K.DecodeReduce(rng.digest(32))
            if not((curve.bp*u**4 + curve.ap*u**2 + curve.K.one).is_square()):
                break
            j += 1
        # We use the binary encoding of the peer public key, so that the
        # ECDH() function applies the alternate secret generation in case
        # of decoding failure.
        secretbad, ok = jq255.ECDH(sk_self, pk_self, bytes(u))
        if ok:
            raise Exception('ECDH should have failed')

        add_test(tl, 'ECDH', { "sk": bytes(sk_self).hex(), "pk1": bytes(pk_peer).hex(), "sec1": secret.hex(), "pk2": bytes(u).hex(), "sec2": secretbad.hex() })

    return tl

def mktests_sign(curve):
    tl = []
    for i in range(0, 20):
        rng = hashlib.shake_256()
        rng.update(curve.bname)
        rng.update(b'-test-sign-sk-')
        rng.update(i.to_bytes(2, 'little'))
        sk = jq255.Keygen(curve, rng)
        pk = jq255.MakePublic(curve, sk)
        rng.update(curve.bname)
        rng.update(b'-test-sign-seed-')
        rng.update(i.to_bytes(2, 'little'))
        seed = rng.digest(i)
        msg = 'sample {0}'.format(i).encode('utf-8')
        h = hashlib.blake2s()
        h.update(msg)
        hv = h.digest()
        sig = jq255.Sign(sk, pk, jq255.HASHNAME_BLAKE2S, hv, seed)
        if not(jq255.Verify(pk, sig, jq255.HASHNAME_BLAKE2S, hv)):
            raise Exception("Cannot verify signature!")
        if jq255.Verify(pk, sig, jq255.HASHNAME_SHA3_256, hv + b'.'):
            raise Exception("Signature verification should have failed!")
        add_test(tl, 'sign', { "sk": bytes(sk).hex(), "pk": bytes(pk).hex(), "seed": seed.hex(), "msg": msg.hex(), "hv": hv.hex(), "sig": sig.hex() })

    return tl

def mktests(curve):
    tm = {}
    tm["decode"] = mktests_decode(curve)
    tm["map"] = mktests_map(curve)
    tm["add"] = mktests_add(curve)
    tm["mul"] = mktests_mul(curve)
    tm["keygen"] = mktests_keygen(curve)
    tm["hashraw"] = mktests_hashraw(curve)
    tm["hashph"] = mktests_hashph(curve)
    tm["ECDH"] = mktests_ECDH(curve)
    tm["sign"] = mktests_sign(curve)
    return tm

if len(sys.argv) >= 2:
    name = sys.argv[1].lower()
    if name == 'jq255e':
        curve = jq255.Jq255e
    elif name == 'jq255s':
        curve = jq255.Jq255s
    else:
        raise Exception('unknown curve name: %s' % name)
else:
    curve = jq255.Jq255e
print(json.dumps(mktests(curve), indent=2))
