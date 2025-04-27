## RSA primes where `GCD(φ(n), e) != 1`

The `rsa.phi-not-coprime-e.2048.txt` file contains two candidate primes for
RSA 2048 key generation, one per line, in big endian hex.

The second prime is congruent to 1 mod 65537, which means φ(n) = (p - 1)(q - 1)
is not coprime with e = 65537.  Therefore, this prime cannot be used in a valid
RSA key.

The first prime is provided so the entire file forms a stand-alone input to
RSA key generation (excluding primality testing input).  This means if you
provide it as input to FIPS186-5 algorithm A.1.3, it fails the condition 5.6.
If you swap the two candidates, it fails the condition 4.5.

### Working

```python
>>> import sympy
>>> p = 0xf68be4166c4bf00a01261d1d51e8a3da28da241cd07d2eb50696c14e7e02de7f83250b669842b0d3cb77e926408377b47b7ed01d54d8ad2ec57a453c3eca57b8faf1caf84c94e383351a0ad2ee179be14c9170b63e6328062689f5569e6cfe4524cd3bff0c2abb7de6d4a80827c1b2cd180e23a8b84a21cee5cd0a9be7306a9d
>>> q = e58b13cc5ae5cf25e685f0c6b5c8eee7d2f3a2a54f3b7520d64d30c36e476f0a42c8183f84695537c94001633d560aa16c8edcc990ff0f30869d7ddab426500763aebf8d27ccfca872696872316e6a378323d9a9a8fa256d16f70601e7b519c22daf63126caf2642253de823ab3d575ee84445bc5bb9aa1df2ae9cb624d0b963
>>> e = 0x10001
>>> all(map(sympy.isprime, [p, q]))
True
>>> phi = (p - 1) * (q - 1)
>>> sympy.gcd(phi, e)
65537
```

The candidate q was found by brute force; one can be expected every 65537 primes.

## License

The vectors in this folder are available under the terms of the
[Zero-Clause BSD](https://opensource.org/licenses/0BSD) license or (at your
option) [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).

> Copyright (c) 2024 The CCTV Authors
>
> Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted.
>
> **The software is provided "as is" and the author disclaims all warranties with
regard to this software including all implied warranties of merchantability and
fitness. In no event shall the author be liable for any special, direct,
indirect, or consequential damages or any damages whatsoever resulting from loss
of use, data or profits, whether in an action of contract, negligence or other
tortious action, arising out of or in connection with the use or performance of
this software.**
