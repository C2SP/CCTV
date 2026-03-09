# ML-DSA signing benchmark targets

ML-DSA signing applies Fiat-Shamir with Aborts, essentially a form of rejection
sampling, which means that the number of iterations required to produce a valid
signature is a random variable with a geometric distribution. This makes simple
benchmarking techniques ineffective, as the variance of the time taken to
produce a signature is very high and would take an impractically large number of
samples to average out.

This directory provides a set of ASCII messages that, when all signed
deterministically with an empty context and a key derived from an all-zero seed,
produce signatures that require a statistically representative distribution of
rejections. **The time taken to sign all of them can be divided by the number of
signatures to obtain an accurate average signing time.** (A similar technique
can be used to [benchmark RSA key generation](https://words.filippo.io/rsa-keygen-bench/).)

The rejection reasons are also represented accurately. The relative distribution
of rejections due to only *z*, only *r₀*, or both *z* and *r₀* are all
representative, so these benchmarks can be used regardless of which rejection
condition is checked first (or even to benchmark the difference).

The distributions are based on both the formulas in Section 3.4 of
[CRYSTALS-Dilithium – Algorithm Specifications and Supporting Documentation
(Version 3.1)](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
and empirical data. Interestingly, the paper only models rejections due to *z*
or *r₀*, and estimates the remaining ones occur “with probability between 1 and
2%.” In practice, *ct₀* rejections almost never happen, while *h* rejections
happen with probabilities between 0.44% and 1.43% depending on parameter sets.
However, if we ignore the signatures that are rejected due to both *h* and one
or both of *z* and *r₀* (the latter of which seems to have a 10% positive
correlation with *h*), the chance of hitting an *h* rejection goes down to
between 0.06% and 0.29%. They are still accurately represented for completeness.

Alternate sets generated with the same process are provided. They can be used to
verify the benchmark is implemented correctly: if replacing the original set
with the alternate set leads to the same overall timings, the benchmark is
correct. (This also serves as a test of the dataset generation process itself.)

The generator is included, although it requires a patched version of the Go
ML-DSA test suite (or another program capable of rapidly generating signatures
and reporting all the rejection checks they fail).
