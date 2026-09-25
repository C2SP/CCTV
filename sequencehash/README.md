# SequenceHash Test Vectors

These test vectors are designed to aid SequenceHash and SequenceMAC implementers in validating and debugging their software. Test vectors are given in JSON format and have the following structure:

```
    "hash_name":    string          # Name of the hash. One of "blake2b", "blake2s", "sha256", "sha512", "sha3_256", or "sha3_512"
    "function_id":  int             # Function ID. 1 for SequenceMAC, 2 for SequenceHash
    "key":          string          # MAC key. This is the hexadecimal representation of a SequenceMAC key. For SequenceHash, this can be ignored and should be set to the empty string.
    "customizer":   string          # Customization string. This is the hexadecimal representation of the customization string used in the final hash computation.
    "inputs":       List of strings # Input bytestrings, each given in hexadecimal
    "may_fail":     boolean         # Indication that the SequenceHash specification _allows_ the implementation to fail to complete (but does not require it to)
    "must_fail":    boolean         # Indication that the SequenceHash specification _requires_ the implementation to fail to complete (typically happens with keys shorter than 32 bytes)
    "may_warn":     boolean         # Indication that the SequenceHash specification allows the implementation to emit a warning
    "final_output": string          # The result of the SequenceHash/SequenceMAC computation, given in hexadecimal
    "inner_hash":   string          # The result of the SequenceHash/SequenceMAC inner hash, given in hexadecimal
    "inner_header": string          # The inner header block, given in hexadecimal
    "outer_header": string          # The outer header block, given in hexadecimal
```
