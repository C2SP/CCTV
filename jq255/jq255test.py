#! /usr/bin/env python3

import importlib
import sys
import json
import jq255

def check_decode(curve, tl):
    print('  decode:  ', flush=True, end='')
    for t in tl:
        data = bytes.fromhex(t['data'])
        decodable = t['decodable']
        if decodable:
            p = curve.Decode(data)
            bb = bytes(p)
            if bb != data:
                raise Exception('bad decode/encode')
        else:
            good = True
            try:
                curve.Decode(data)
            except Exception:
                good = False
            if good:
                raise Exception('decoding should have failed')
    print('OK', flush=True)

def check_map(curve, tl):
    print('  map:     ', flush=True, end='')
    for t in tl:
        q = curve.MapToCurve(bytes.fromhex(t['f']))
        if bytes(q) != bytes.fromhex(t['p']):
            raise Exception('bad map-to-group')
    print('OK', flush=True)

def check_add(curve, tl):
    print('  add:     ', flush=True, end='')
    for t in tl:
        ep1 = bytes.fromhex(t['p1'])
        ep2 = bytes.fromhex(t['p2'])
        ep3 = bytes.fromhex(t['p3'])
        ep4 = bytes.fromhex(t['p4'])
        ep5 = bytes.fromhex(t['p5'])
        ep6 = bytes.fromhex(t['p6'])
        p1 = curve.Decode(ep1)
        p2 = curve.Decode(ep2)
        p3 = p1 + p2
        if bytes(p3) != ep3:
            raise Exception('add 1')
        p4 = p1.Double()
        if bytes(p4) != ep4:
            raise Exception('add 2')
        q4 = p1 + p1
        if bytes(q4) != ep4:
            raise Exception('add 3')
        p5 = p4 + p2
        if bytes(p5) != ep5:
            raise Exception('add 4')
        q5 = p1 + p3
        if bytes(q5) != ep5:
            raise Exception('add 5')
        p6 = p3.Double()
        if bytes(p6) != ep6:
            raise Exception('add 6')
        q6 = p4 + p2.Double()
        if bytes(q6) != ep6:
            raise Exception('add 7')
        r3 = q6 - p3
        if bytes(r3) != ep3:
            raise Exception('add 8')
        r2 = q6 - q5
        if bytes(r2) != ep2:
            raise Exception('add 9')
        q = p1
        for j in range(1, 10):
            q += q
            if bytes(q) != bytes(p1.Xdouble(j)):
                raise Exception('xdouble %d' % j)
    print('OK', flush=True)

def check_mul(curve, tl):
    print('  mul:     ', flush=True, end='')
    for t in tl:
        p = curve.Decode(bytes.fromhex(t['p']))
        s = curve.SF.Decode(bytes.fromhex(t['s']))
        if bytes(s*p) != bytes.fromhex(t['q']):
            raise Exception('mul')
    print('OK', flush=True)

def check_keygen(curve, tl):
    print('  keygen:  ', flush=True, end='')
    for t in tl:
        sk = jq255.DecodePrivate(curve, bytes.fromhex(t['sk']))
        pk = jq255.MakePublic(curve, sk)
        if jq255.EncodePublic(pk) != bytes.fromhex(t['pk']):
            raise Exception('keygen')
    print('OK', flush=True)

def check_hashraw(curve, tl):
    print('  hashraw: ', flush=True, end='')
    for t in tl:
        raw = bytes.fromhex(t['raw'])
        p = jq255.HashToCurve(curve, None, raw)
        if bytes(p) != bytes.fromhex(t['p']):
            raise Exception('hashraw')
    print('OK', flush=True)

def check_hashph(curve, tl):
    print('  hashph:  ', flush=True, end='')
    for t in tl:
        hv = bytes.fromhex(t['hv'])
        p = jq255.HashToCurve(curve, jq255.HASHNAME_BLAKE2S, hv)
        if bytes(p) != bytes.fromhex(t['p']):
            raise Exception('hashph')
    print('OK', flush=True)

def check_ECDH(curve, tl):
    print('  ECDH:    ', flush=True, end='')
    for t in tl:
        sk = jq255.DecodePrivate(curve, bytes.fromhex(t['sk']))
        q = jq255.MakePublic(curve, sk)
        pk1 = bytes.fromhex(t['pk1'])
        (sec1, ok1) = jq255.ECDH(sk, q, pk1)
        if not(ok1) or sec1 != bytes.fromhex(t['sec1']):
            raise Exception('ECDH 1')
        pk2 = bytes.fromhex(t['pk2'])
        (sec2, ok2) = jq255.ECDH(sk, q, pk2)
        if ok2 or sec2 != bytes.fromhex(t['sec2']):
            raise Exception('ECDH 2')
    print('OK', flush=True)

def check_sign(curve, tl):
    print('  sign:    ', flush=True, end='')
    for t in tl:
        sk = jq255.DecodePrivate(curve, bytes.fromhex(t['sk']))
        pk = jq255.MakePublic(curve, sk)
        if jq255.EncodePublic(pk) != bytes.fromhex(t['pk']):
            raise Exception('sign 1')
        seed = bytes.fromhex(t['seed'])
        hv = bytes.fromhex(t['hv'])
        sig = jq255.Sign(sk, pk, jq255.HASHNAME_BLAKE2S, hv, seed)
        if sig != bytes.fromhex(t['sig']):
            raise Exception('sign 2')
        sig = bytearray(sig)
        hv = bytearray(hv)
        if not(jq255.Verify(pk, sig, jq255.HASHNAME_BLAKE2S, hv)):
            raise Exception('sign 3')
        hv[11] ^= 0x01
        if jq255.Verify(pk, sig, jq255.HASHNAME_BLAKE2S, hv):
            raise Exception('sign 4')
        hv[11] ^= 0x01
        if not(jq255.Verify(pk, sig, jq255.HASHNAME_BLAKE2S, hv)):
            raise Exception('sign 5')
        sig[13] ^= 0x01
        if jq255.Verify(pk, sig, jq255.HASHNAME_BLAKE2S, hv):
            raise Exception('sign 6')
    print('OK', flush=True)

def check(curve):
    f = open('test-%s.json' % curve.name)
    tm = json.load(f)
    f.close()
    print('Tests %s:' % curve.name, flush=True)
    check_decode(curve, tm['decode'])
    check_map(curve, tm['map'])
    check_add(curve, tm['add'])
    check_mul(curve, tm['mul'])
    check_keygen(curve, tm['keygen'])
    check_hashraw(curve, tm['hashraw'])
    check_hashph(curve, tm['hashph'])
    check_ECDH(curve, tm['ECDH'])
    check_sign(curve, tm['sign'])

check(jq255.Jq255e)
check(jq255.Jq255s)
