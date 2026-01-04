## RSA key generation benchmark

The `rsa.bench.NNNN.txt` files are a sequence of prime candidates for RSA key
generation, one per line, in big endian hex. Each file contains two primes, the
second of which is on the last line, and a number of composites. The totients of
the primes are coprime with 65537. All candidates have the top two and the
bottom three bits set.

The number of composites, the distribution of their small divisors, and the
number of trailing zeros are all chosen to be representative of the expected
average. See [this article](https://words.filippo.io/rsa-keygen-bench/)
for more details.

This file can be used to reproducibly benchmark the average case of RSA key
generation, which otherwise has a drastically variable geometric distribution.

## License

The vectors and code in this folder are available under the terms of the
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
