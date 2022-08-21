The test vectors in the `ed25519vectors.json` file exercise a complete set of
edge cases for the elliptic curve point inputs (the public key `A` and the first
half `R` of the signature) to Ed25519 signature verification.

The behavior in handling these signatures is not relevant to the basic security
properties of Ed25519, but behavior inconsistencies or changes can be an issue
for consensus applications, and protocols might happen to rely on extended
security properties that require rejecting some or all of these signatures.

See https://hdevalence.ca/blog/2020-10-04-its-25519am for more details. This set
of vectors is an extension of those discussed in that article.

## Vectors format

Each vector provides a hex-encoded signature (`sig`) from a hex-encoded public
key (`key`) on a plain message (`msg`), as well as a set of flags that detail
what edge cases the vector exercises.

### Flags descriptions

* `low_order_A` and `low_order_R`

  These vectors have a point that is one of a small set (eight plus six
  alternative encodings) of low-order points.

* `non_canonical_A` and `non_canonical_R`

  These vectors have a point that is an alternative, non-canonical encoding of
  one of the low-order points.

* `low_order_component_A` and `low_order_component_R`

  These vectors have a point that has a low-order component, but might also have
  a prime-order component. These signatures will still behave differently
  depending on the verification formula in use, but the points can't be rejected
  through the use of a blocklist or by multiplying by the cofactor, unless they
  are also flagged `low_order`.

* `low_order_residue`

  In these vectors the low order components of R and [k]A don't cancel out, so
  they will only verify with formulae that multiply the two points by the
  cofactor.

## Ecosystem behaviors

RFC8032 requires rejecting `non_canonical_A` and `non_canonical_R`, allows both
rejecting and accepting `low_order_residue` depending on what formula is used,
and is silent on the rest.

The most common verification behavior, derived from the "ref10" implementation
and exhibited by Go and OpenSSL amongst others, is to reject `low_order_R` and
`low_order_residue` and to accept everything else.

ZIP215 rules require accepting all vectors.

Recent libsodium and ed25519-dalek's `verify_strict()` reject all vectors.

## Low-order edwards25519 point encodings

For reference, here we list the encodings of edwards25519 low-order points. Note
that any blocklist-based approach can't reject points with both a low-order and
a prime-order component, which may or may not achieve any desired security goal.

The points are listed hex-encoded, in lexicographical order, with alternative
encodings listed indented below them.

```
0000000000000000000000000000000000000000000000000000000000000000 [order 4]
    edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f (y > p)

0000000000000000000000000000000000000000000000000000000000000080 [order 4]
    edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff (y > p)

0100000000000000000000000000000000000000000000000000000000000000 [order 1]
    0100000000000000000000000000000000000000000000000000000000000080 (x = 0)
    eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f (y > p)
    eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff (x = 0, y > p)

26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 [order 8]

26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 [order 8]

c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a [order 8]

c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa [order 8]

ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f [order 2]
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff (x = 0)
```

Note that libsodium 1.0.15 includes a partial list in `ed25519/ref10/open.c`,
which is missing three encodings, and includes five other encodings: on is not a
valid point, one has a prime-order component, and three are Montgomery low-order
points.
