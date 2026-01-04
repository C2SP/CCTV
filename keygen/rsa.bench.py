# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "sympy",
#     "mpmath",
# ]
# ///

from sympy import isprime, primerange
from random import randrange, shuffle
from mpmath import li
from sys import argv

BIT_SIZE = int(argv[1]) // 2 if len(argv) > 1 else 1024

PRIMES: list[int] = list(primerange(3, 1000000)) # type: ignore

# Ratio of odd integers less than 2^BIT_SIZE that are prime.
# Li(2^BIT_SIZE) / 2^BIT_SIZE * 2
PRIME_RATIO = float(li(2**BIT_SIZE) / 2**(BIT_SIZE - 1))

# Ratio of odd integers divisible by primes[:n].
SMALLDIV_RATIOS: list[float] = [0]

for p in PRIMES:
    SMALLDIV_RATIOS.append(1 - (1 - SMALLDIV_RATIOS[-1]) * ((p - 1) / p))

count = int(round(1 / PRIME_RATIO, 0))

# Buckets of values in each expected category.
small_divisor = []
composite = {"want": count - int(round(count * SMALLDIV_RATIOS[-1])) - 1, "have": []}
prime = {"want": 1, "have": []}

prev = 0
for i in range(1, len(SMALLDIV_RATIOS)):
    want = int(round(count * SMALLDIV_RATIOS[i] - prev, 0))
    if want > 0:
        prev += want
        small_divisor.append({
            "nprimes": i,
            "want": want,
            "have": [],
        })

done = lambda: all(len(bucket["have"]) >= bucket["want"] for bucket in small_divisor) and \
    len(composite["have"]) >= composite["want"] and len(prime["have"]) >= prime["want"]

while not done():
    x = randrange(2**(BIT_SIZE-1) + 2**(BIT_SIZE-2) + 1, 2**BIT_SIZE, 2) | 0b111
    if isprime(x):
        prime["have"].append(x)
        continue
    for n, p in enumerate(PRIMES, start=1):
        if x % p == 0:
            for bucket in small_divisor:
                if n <= bucket["nprimes"]:
                    bucket["have"].append(x)
                    break
            break
    else:
        composite["have"].append(x)

out = []
for bucket in small_divisor:
    out.extend(bucket["have"][:bucket["want"]])
out.extend(composite["have"][:composite["want"]])
shuffle(out)
out.extend(prime["have"][:prime["want"]])

for x in out:
    print(hex(x)[2:])
