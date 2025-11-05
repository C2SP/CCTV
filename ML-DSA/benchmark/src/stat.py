import sys

if sys.argv[1] == "44":
    results = [7368698, 6238419, 9743544, 8252486, 0, 0, 0, 0, 93720, 79660, 154045, 131188, 1, 0, 0, 0]
    q = 8380417
    gamma1 = 2 ** 17
    gamma2 = (q - 1)/88
    beta = 78
    k, l = 4, 4
elif sys.argv[1] == "65":
    results = [4440848, 2731767, 9616285, 5919454, 0, 0, 0, 0, 14486, 9201, 47356, 29001, 0, 0, 0, 0]
    q = 8380417
    gamma1 = 2 ** 19
    gamma2 = (q - 1)/32
    beta = 196
    k, l = 6, 5
elif sys.argv[1] == "87":
    results = [4102322, 2088997, 6415247, 3270072, 0, 0, 0, 0, 29599, 15086, 61093, 30983, 0, 0, 0, 0]
    q = 8380417
    gamma1 = 2 ** 19
    gamma2 = (q - 1)/32
    beta = 120
    k, l = 8, 7
else: 
    print("usage: stat.py [44|65|87]")
    sys.exit(1)

checks = ["z", "r0", "ct0", "h"]

total = sum(results)
pass_prob = results[0] / total
z = sum(results[j] for j in range(16) if (j & 0b0001))
z_prob = z / total
r0 = sum(results[j] for j in range(16) if (j & 0b0010))
r0_prob = r0 / total
ct0 = sum(results[j] for j in range(16) if (j & 0b0100))
ct0_prob = ct0 / total
h = sum(results[j] for j in range(16) if (j & 0b1000))
h_prob = h / total
z_and_r0 = sum(results[j] for j in range(16) if (j & 0b0001) and (j & 0b0010))
z_and_r0_prob = z_and_r0 / total
z_and_h = sum(results[j] for j in range(16) if (j & 0b0001) and (j & 0b1000))
z_and_h_prob = z_and_h / total
r0_and_h = sum(results[j] for j in range(16) if (j & 0b0010) and (j & 0b1000))
r0_and_h_prob = r0_and_h / total
not_z_or_r0 = sum(results[j] for j in range(16) if not (j & 0b0011))
not_z_or_r0_prob = not_z_or_r0 / total
z_not_r0 = sum(results[j] for j in range(16) if (j & 0b0001) and not (j & 0b0010))
z_not_r0_prob = z_not_r0 / total
r0_not_z = sum(results[j] for j in range(16) if (j & 0b0010) and not (j & 0b0001))
r0_not_z_prob = r0_not_z / total
only_h = results[0b1000]
only_h_prob = only_h / total

print(f"none: {pass_prob:.4f}")
print(f"repetitions: {1 / pass_prob:.2f}")
print(f"z:    {z_prob:.4f}")
print(f"r0:   {r0_prob:.4f}")
print(f"ct0:  {ct0_prob:.4f}")
print(f"h:    {h_prob:.4f}")
print(f"not(z | r0): {not_z_or_r0_prob:.4f}")
print(f"only h:      {only_h_prob:.4f}")

# print expected z value: (1 - (β / (γ1-1/2))) ^ 256l
expected_z = 1 - (1 - (beta / (gamma1 - 0.5))) ** (256 * l)
print(f"expected z:  {expected_z:.4f}")

# print expected r0 value: ((2(γ2−β)−1) / 2γ2) ^ 256k
expected_r0 = 1 - ((2 * (gamma2 - beta) - 1) / (2 * gamma2)) ** (256 * k)
print(f"expected r0: {expected_r0:.4f}")

print(f"expected not(z | r0): {(1 - expected_z) * (1 - expected_r0):.4f}")
print(f"expected repetitions: {1 / ((1 - expected_z) * (1 - expected_r0)):.2f}")

# print pairwise correlations between z, r0, and h
print("pairwise occurrences:")

# z and r0
expected_z_and_r0 = z_prob * r0_prob
print(f"z and r0:    actual {z_and_r0 / total:.4f}, expected {expected_z_and_r0:.4f}, ratio {(z_and_r0 / total) / expected_z_and_r0:.2f}")

# z and h
expected_z_and_h = z_prob * h_prob
print(f"z and h:     actual {z_and_h / total:.4f}, expected {expected_z_and_h:.4f}, ratio {(z_and_h / total) / expected_z_and_h:.2f}")

# r0 and h
expected_r0_and_h = r0_prob * h_prob
print(f"r0 and h:    actual {r0_and_h / total:.4f}, expected {expected_r0_and_h:.4f}, ratio {(r0_and_h / total) / expected_r0_and_h:.2f}")

passes_to_error = {n: abs(round(n / pass_prob) - (n / pass_prob)) for n in range(100, 200)}
passes_with_lowest_error = min(passes_to_error.items(), key=lambda x: x[1])[0]
trials = passes_with_lowest_error / pass_prob

# z and r0 are checked before h, so we can ignore h for the z and/or r0 values

passes = round(trials * pass_prob)
fails_only_z = round(trials * z_not_r0_prob)
fails_only_r0 = round(trials * r0_not_z_prob)
fails_z_and_r0 = round(trials * z_and_r0_prob)
fails_only_h = round(trials * only_h_prob)
total_sum = passes + fails_only_z + fails_only_r0 + fails_z_and_r0 + fails_only_h

print(f"\nExpected trials: {trials}")
print(f"Total trials: {total_sum}")
print(f"  - Passes:         {passes}")
print(f"  - Fails only z:   {fails_only_z}")
print(f"  - Fails only r0:  {fails_only_r0}")
print(f"  - Fails z and r0: {fails_z_and_r0}")
print(f"  - Fails only h:   {fails_only_h}")

floor = lambda x: int(x // 1)
ceil = lambda x: int(-(-x // 1))

# sample returns an input message, and a list of rejection causes it encounters,
# from "z", "r0", "z/r0", "h".
def sample():
    # Running "bin/go test crypto/internal/fips140/mldsa -run TestSample/ML-DSA-44 -v -count 1" produces:
    #
    #    === RUN   TestSample
    #    === RUN   TestSample/ML-DSA-44
    #    seed: ZAI62RWMNI4MANGIWMBGAT7BME
    #    rejection: r0
    #    rejection: z/r0
    #    rejection: z
    #    rejection: r0
    #    --- PASS: TestSample (0.00s)
    #        --- PASS: TestSample/ML-DSA-44 (0.00s)
    #    PASS
    #    ok  	crypto/internal/fips140/mldsa	0.183s
    import subprocess
    proc = subprocess.run(
        ["./mldsa.test", "-test.run", f"TestSample/ML-DSA-{sys.argv[1]}", "-test.v", "-test.count", "1"],
        capture_output=True,
        text=True,
    )
    lines = proc.stdout.splitlines()
    seed_line = next(line for line in lines if line.startswith("seed: "))
    seed = seed_line[len("seed: "):]
    rejections = [line[len("rejection: "):] for line in lines if line.startswith("rejection: ")]
    return (seed, rejections)

remaining_only_z = fails_only_z
remaining_only_r0 = fails_only_r0
remaining_z_and_r0 = fails_z_and_r0
remaining_only_h = fails_only_h
samples = []
while len(samples) < passes:
    msg, rejections = sample()
    count_only_z = sum(1 for r in rejections if r == "z")
    count_only_r0 = sum(1 for r in rejections if r == "r0")
    count_z_and_r0 = sum(1 for r in rejections if r == "z/r0")
    count_only_h = sum(1 for r in rejections if r == "h")
    remaining_pass = passes - len(samples)

    # skip if more than double the expected rejections
    if len(rejections) > 2 * ((total_sum - passes) / passes):
        continue

    if (count_only_h > remaining_only_h or
        count_only_z > remaining_only_z or
        count_only_r0 > remaining_only_r0 or
        count_z_and_r0 > remaining_z_and_r0):
        continue

    if ((remaining_only_r0 >= remaining_pass and count_only_r0 == 0) or
        (remaining_only_z >= remaining_pass and count_only_z == 0) or
        (remaining_z_and_r0 >= remaining_pass and count_z_and_r0 == 0) or
        (remaining_only_h >= remaining_pass and count_only_h == 0)):
        continue

    print(f"selected sample with rejections: {rejections}")
    print(f"remaining: z={remaining_only_z}, r0={remaining_only_r0}, z_and_r0={remaining_z_and_r0}, h={remaining_only_h} passes={remaining_pass}")
    samples.append(msg)
    remaining_only_z -= count_only_z
    remaining_only_r0 -= count_only_r0
    remaining_z_and_r0 -= count_z_and_r0
    remaining_only_h -= count_only_h
from random import shuffle
shuffle(samples)
for sample in samples:
    print(f"\t\"{sample}\",")
