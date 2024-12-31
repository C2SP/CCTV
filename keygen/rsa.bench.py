# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "sympy",
# ]
# ///

from sympy import isprime, primerange
from random import randrange, shuffle

PRIMES = list(primerange(3, 1000000))

# Ratio of odd integers less than 2^1024 that are prime.
# Li(2^1024) / 2^1024 * 2
PRIME_RATIO = 0.002821744

# Ratio of odd integers divisible by primes[:n].
SMALLDIV_RATIOS = [0]

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
    x = randrange(2**1023 + 2**1022 + 1, 2**1024, 2)
    x = (x & ~0b10) | 0b100 # normalize a in Miller-Rabin
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
