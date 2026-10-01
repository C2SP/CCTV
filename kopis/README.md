# Test vectors for Kopis

This directory contains three Python files:

* `kopis.py` — An implementation of the [Kopis](https://c2sp.org/kopis) key encapsulation mechanism (KEM)
* `test_kopis.py` — Unit tests for `kopis.py`
* `gen_test_vectors.py` — A deterministic Kopis test vector generator

## How to Run

An installation of [`uv`](https://docs.astral.sh/uv/) is assumed.

To generate test vectors: `uv run python gen_test_vectors.py`

To run unit tests: `uv run python -m pytest`

## Test vector structure

The generator produces three test vector files, one for each security level of Kopis. Each file is JSONL, meaning it has a single JSON object per line. Each JSON object is comprised of:

field | type | desc |
------|------|------|
`description` | string | An English description of what the test vector is intended to test |
`number` | number | A unique numerical identifier of this test vector |
`sk` | bytestring | The KEM secret key |
`pk` | bytestring | The serialized KEM public key corresponding to `sk` |
`encap_randomness` | bytestring | The randomness used to encapsulate to `pk` |
`encapper_ct` | bytestring | The serialized ciphertext produced by the encapsulation |
`decapper_ct` | bytestring | The ciphertext handed to the decapsulator. May differ from `encapper_ct`. |
`encapper_ss` | bytestring  | The shared secret from the encapsulation that produced `encapper_ct` |
`decapper_ss` | bytestring | The shared secret from decapsulating `decapper_ct` with `sk`. |
`malformed`   | bool | Whether a value above is malformed, i.e., the wrong length |

All bytestrings are represented as a lowercase hex string.

If a test is marked `malformed`, then there is at least one field that should cause an error when parsing. If no errors occur when parsing, this should be considered an implementation flaw.
