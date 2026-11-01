# Test Vectors for Kopis

This directory contains three Python files:

* `kopis.py` — An implementation of the [Kopis](https://c2sp.org/kopis) key encapsulation mechanism (KEM). DANGER: this is not constant-time. Use it ONLY for generating and checking test vectors.
* `test_kopis.py` — Unit tests for `kopis.py`.
* `gen_test_vectors.py` — A deterministic Kopis test vector generator. This is what generated the `.jsonl` files in this directory.

## How to Run

First, you need [`uv`](https://docs.astral.sh/uv/) installed.

To generate test vectors: `uv run python gen_test_vectors.py`

To run unit tests: `uv run python -m pytest`

## Test vector structure

There are three test vector files, `test_vectors_kopis512.jsonl`,  `test_vectors_kopis768.jsonl`, and  `test_vectors_kopis1024.jsonl`, one for each security level. Each file is JSONL, meaning it has a single JSON object per line. Each JSON object is comprised of:

field | type | desc |
------|------|------|
`description` | string | An English description of what the test vector is intended to test |
`number` | number | A unique numerical identifier of this test vector |
`sk` | bytestring | The KEM secret key |
`pk` | bytestring | The serialized KEM public key corresponding to `sk`. |
`encap_randomness` | bytestring | The randomness used to encapsulate to `pk`. |
`encapper_ct` | bytestring | The serialized ciphertext produced by the encapsulation. |
`decapper_ct` | bytestring | The ciphertext handed to the decapsulator. May differ from `encapper_ct`. |
`encapper_ss` | bytestring  | The shared secret from the encapsulation that produced `encapper_ct`. |
`decapper_ss` | bytestring | The shared secret from decapsulating `decapper_ct` with `sk`. May differ from `encapper_ss`. |
`malformed`   | bool | Whether a value above is malformed, i.e., the wrong length. |

All bytestrings are represented as a lowercase hex string. Test vector numbers are unique across all three files.

If a test is marked `malformed`, then there is at least one field that should cause an error when parsing. If no errors occur when parsing, this should be considered an implementation flaw.

The output fields of a malformed vector are still filled in. They are what an implementation _would_ produce if it silently coerced the bad value to the expected length, zero-padding a value that is too short and truncating one that is too long, and then carried on as normal. An implementation that reproduces these outputs has exactly that bug. The `description` field says which value is malformed and how the outputs were derived.
