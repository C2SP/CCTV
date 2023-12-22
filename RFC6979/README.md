# RFC 6979 rejection sampling vector

RFC 6979 details how to deterministically derive the ECDSA nonce from the private key and message.
The selection is performed by rejection sampling. The chance of rejection depends on the order of the curve.
P-256 has a 2⁻³² chance of randomly hitting a rejection. For P-224 it's 2⁻¹¹², for P-384 it's 2⁻¹⁹⁴, and for P-521 it's 2⁻²⁶².

This means that concretely, RFC 6979 with P-256 can reject the first k candidate and should be tested,
while with other NIST curves the chance is negligible, making it both impossible and unnecessary to test.

This is a test vector that causes a rejection, in the same format as RFC 6979, Appendix A.
Specifically, it reuses the private key from RFC 6979, Appendix A.2.5.

```
Key pair:

curve: NIST P-256

q = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
(qlen = 256 bits)

private key:

x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

public key: U = xG

Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6

Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299

Signatures:

With SHA-256, message = "wv[vnX":
k = 2AE40DF9D9DAB61D688DE3DCB9867A98ECC70DD4D6C0F6C228B6E4E0B18B29BC
r = EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234
s = 3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33
```

This vector was checked against github.com/codahale/rfc6979 (https://go.dev/play/p/FK5-fmKf7eK),
OpenSSL 3.2.0 (https://github.com/openssl/openssl/pull/23130), and python-ecdsa.
