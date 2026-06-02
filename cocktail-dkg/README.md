# Test vectors for cocktail-dkg

Spec: <https://c2sp.org/cocktail-dkg>

These are current as of v0.2.0 of the cocktail-dkg spec.

## Seed Derivation

The test vectors are generated from a SHA256 hash of the spec co-maintainers' names:

```text
seed = SHA256("Daniel Bourdrez,Soatok Dreamseeker,Tjaden Hess")
     = b171b6992cc6db1f40b18dd8b1361d642f013e4b1208a735259a516af60dcb68
```

All secret values are derived using a labeled hash with ciphersuite and threshold domain separation:

```text
derived_bytes = H(seed || ciphersuite_id || uint32_le(t) || uint32_le(n) || label)
```

Where:

- `H` is the ciphersuite's hash function
- `ciphersuite_id` is the ciphersuite identifier string
- `t` is the threshold (little-endian 32-bit unsigned integer)
- `n` is the number of participants (little-endian 32-bit unsigned integer)
- `label` is a human-readable ASCII string identifying the value

## Test Vector Types

Each JSON file contains multiple test vectors:

1. **2-of-3 basic**: Standard 2-of-3 DKG with empty extension
2. **3-of-5 basic**: Standard 3-of-5 DKG with empty extension
3. **7-of-14 basic**: Standard 7-of-14 DKG with empty extension
4. **2-of-3 with payload extension**: 2-of-3 DKG where each participant includes a
   seed-derived payload, and the extension is a hash of all payloads

## JSON Structure

Each vector includes:

- `name`: Descriptive name for the test case
- `n`: Total number of participants
- `t`: Threshold
- `context`: Context string (hex-encoded)
- `extension`: Application-specific extension (hex-encoded, empty string if none)
- `payloads`: (Optional) Array of hex-encoded payloads for each participant
- `config`: Static keys for all participants
- `round1`: Ephemeral keys, VSS commitments, PoPs, and encrypted shares
- `round2`: Secret shares and verification shares
- `round3`: Transcript hash and signatures
- `group_public_key`: Final group public key

## Ciphersuites

| File                                    | Ciphersuite                      |
|-----------------------------------------|----------------------------------|
| `cocktail-dkg-ristretto255-sha512.json` | COCKTAIL(Ristretto255, SHA-512)  |
| `cocktail-dkg-ed25519-sha512.json`      | COCKTAIL(Ed25519, SHA-512)       |
| `cocktail-dkg-p256-sha256.json`         | COCKTAIL(P-256, SHA-256)         |
| `cocktail-dkg-secp256k1-sha256.json`    | COCKTAIL(secp256k1, SHA-256)     |
| `cocktail-dkg-ed448-shake256.json`      | COCKTAIL(Ed448, SHAKE256)        |
| `cocktail-dkg-jubjub-blake2b512.json`   | COCKTAIL(JubJub, BLAKE2b-512)    |
| `cocktail-dkg-pallas-blake2b512.json`   | COCKTAIL(Pallas, BLAKE2b-512)    |
