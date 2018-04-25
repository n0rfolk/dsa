import sys
import getopt
import secrets
import hashlib
import sympy
import math

'''
    DSA - Digital Signature Algorithm
    @author = n0rfolk
    Based on publication FIPS 186-4
'''

# Chosen Hash() function SHA256, so outlen = 256
outlen = 256

# Fast modular exponentation
def fast_modular_expn(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while (exponent > 0):
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

# Primality test
def primality_test(number):
    return sympy.isprime(number)

# Calculating chosen hash() function (sha256)
def hash(input):
    return int(hashlib.sha256(str(input).encode()).hexdigest(), 16)

# Generating p and q using Shawe-Taylor Algorithm
def st_random_prime(length, input_seed):
    if length < 2:
        return 'FAILURE', 0, 0, 0

    if length >= 33:
        status, c_0, prime_seed, prime_gen_counter = st_random_prime(math.ceil(length/2) + 1, input_seed)

        if status == 'FAILURE':
            return 'FAILURE', 0, 0, 0

        iterations = math.ceil(length/outlen) - 1
        old_counter = prime_gen_counter
        x = 0
        for i in range(iterations):
            x = x + (hash(prime_seed + i) * (1 << (i * outlen)))
        prime_seed = prime_seed + iterations + 1
        x = (1 << (length - 1)) + x % (1 << (length - 1))
        t = math.ceil(x/(2 * c_0))

        while True:
            if (2 * t * c_0 + 1 > (1 << length)):
                t = math.ceil(((1 << (length - 1)))/(2 * c_0))
            c = 2 * t * c_0 + 1
            prime_gen_counter = prime_gen_counter + 1
            a = 0
            for i in range(iterations):
                a = a + (hash(prime_seed + i) * (1 << (i * outlen)))
            prime_seed = prime_seed + iterations + 1
            a = 2 + (a % (c - 3))
            z = fast_modular_expn(a, 2 * t, c)

            if (1 == math.gcd(z - 1, c)) and (1 == fast_modular_expn(z, c_0, c)):
                prime = c
                return 'SUCCESS', prime, prime_seed, prime_gen_counter

            if (prime_gen_counter >= 4 * length + old_counter):
                return 'FAILURE', 0, 0, 0

            t += 1

    prime_seed = input_seed
    prime_gen_counter = 0

    while True:
        c = hash(prime_seed) ^ hash(prime_seed + 1)
        c = (1 << (length - 1)) + (c % (1 << (length - 1)))
        c = (2 * math.floor(c/2) + 1)

        prime_gen_counter = prime_gen_counter + 1
        prime_seed = prime_seed + 2

        if primality_test(c):
            prime = c
            return 'SUCCESS', prime, prime_seed, prime_gen_counter

        if prime_gen_counter > 4*length:
            return 'FAILURE', 0, 0, 0

# First seed generation
def first_seed(N, seedlen=256):
    acceptable_values = [160, 224, 256]

    status = 'FAILURE'
    firstseed = 0

    if N not in acceptable_values:
        return status, firstseed

    if(seedlen < N):
        return status, firstseed

    while firstseed < (1 << (N - 1)):
        firstseed = secrets.randbits(seedlen)

    return 'SUCCESS', firstseed

# Constructing primes
def constructive_prime_gen(L, N, firstseed):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    status = 'FAILURE'

    if (L, N) not in acceptable_values:
        return status

    status, q, qseed, qgen_counter = st_random_prime(N, firstseed)
    if status == 'FAILURE':
        return -1, -1

    status, p_0, pseed, pgen_counter = st_random_prime(math.ceil(L/2 + 1), qseed)
    if status == 'FAILURE':
        return -1, -1

    iterations = math.ceil(L/outlen) - 1
    old_counter = pgen_counter

    x = 0
    for i in range(iterations):
        x += hash(pseed + i) * (1 << (i * outlen))
    pseed += iterations + 1
    x = (1 << (L - 1)) + x % (1 << (L - 1))

    t = x//(2 * q * p_0)

    while True:
        if 2 * t * q * p_0 + 1 > (1 << L):
            t = math.ceil(((1 << (L - 1)))/(2 * q * p_0))
        p = 2 * t * q * p_0 + 1
        pgen_counter += 1

        a = 0
        for i in range(iterations):
            a += hash(pseed + i) * (1 << (i * outlen))
        pseed += iterations + 1
        a = 2 + a % (p - 3)
        z = fast_modular_expn(a, 2 * t * q, p)

        if (1 == math.gcd(z - 1, p)) and (1 == fast_modular_expn(z, p_0, p)):
            return 'SUCCESS', p, q, pseed, qseed, pgen_counter, qgen_counter

        if pgen_counter > 4 * L + old_counter:
            return -1, -1

        t += 1
'''
def generation_pq_approved_hash(L, N, seedlen):
    # Init
    [status, p, q, domain_parameter_seed, counter] = ["INVALID", 0, 0, 0, 0]
    # Acceptable values of (L, N)
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    # Check if (L, N) in acceptable list and if seedlen > N
    if (L, N) not in acceptable_values:
        return status, p, q, domain_parameter_seed, counter

    if (seedlen < N):
        return status, p, q, domain_parameter_seed, counter

    # Now we can return to the generation process
    while True:
        n = math.ceil(L / outlen) - 1
        b = L - 1 - (n * outlen)
        domain_parameter_seed = secrets.randbits(seedlen)
        U = hash(domain_parameter_seed) % (1 << (N - 1))
        q = (1 << (N - 1)) + U + 1 - (U % 2)
        offset = 1
        if primality_test(q):
            for counter in range(4*L):
                V = []
                W = 0
                for j in range(n):
                    V.append(hash((domain_parameter_seed + offset + j) % (1 << (seedlen))))
                    W = W + V[j] * (1 << (j * outlen))
                V.append(hash((domain_parameter_seed + offset + n) % (1 << (seedlen))))
                W = W + (V[n] % (1 << (b))) * (1 << (n * outlen))
                X = W + (1 << (L - 1))
                c = X % (2 * q)
                p = X - (c - 1)
                if p < (1 << (L - 1)):
                    offset = offset + n + 1
                else:
                    if primality_test(p):
                        return "VALID", p, q, domain_parameter_seed, counter
'''
# Validation of constructed p and q using Shawe-Taylor's method
def validation_pq_st(p, q, seed, pgen_counter, qgen_counter):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    firstseed = seed[0]
    pseed = seed[1]
    qseed = seed[2]

    L = (p.bit_length() + 1, p.bit_length())[p.bit_length() % 2 == 0]
    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]

    # Checks for failures
    if (L, N) not in acceptable_values:
        return "FAILURE"

    if firstseed < (1 << N - 1):
        return "FAILURE"

    if (1 << N) <= q:
        return "FAILURE"

    if (1 << L) <= p:
        return "FAILURE"

    if ((p - 1) % q != 0):
        return "FAILURE"

    status, p_val, q_val, pseed_val, qseed_val, pgen_counter_val, qgen_counter_val = constructive_prime_gen(L, N, firstseed)

    result_set = {status == "SUCCESS", p_val == p, q_val == q, pseed_val == pseed, qseed_val == qseed, pgen_counter_val == pgen_counter, qgen_counter_val == qgen_counter}

    if False in result_set:
        return "FAILURE"

    return "SUCCESS"

# Generation of g using verifiable method
def verif_gen_g(p, q, domain_parameter_seed, index=1):
    if index < 1 or index.bit_length() > 8:
        return "INVALID"

    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]
    e = (p - 1) // q
    count = 0
    g = 1
    while g < 2:
        count += 1

        if (count == 0):
            return "INVALID"

        U = str(domain_parameter_seed) + str(int("0x6767656E", 16)) + str(index) + str(count)
        W = int(hashlib.sha256(U.encode()).hexdigest(), 16)
        g = fast_modular_expn(W, e, p)

    return g

# g validation
def g_validation(p, q, domain_parameter_seed, g, index=1):
    if index < 1 or index.bit_length() > 8:
        return "INVALID"

    if 2 <= g <= (p - 1):
        if fast_modular_expn(g, q, p) == 1:
            N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]
            e = (p - 1) // q
            count = 0
            computed_g = 1
            while computed_g < 2:
                count += 1

                if (count == 0):
                    return "INVALID"

                U = str(domain_parameter_seed) + str(int("0x6767656E", 16)) + str(index) + str(count)
                W = int(hashlib.sha256(U.encode()).hexdigest(), 16)
                computed_g = fast_modular_expn(W, e, p)

            if computed_g == g:
                return "VALID"

            return "INVALID"

# Generation of key pair
def key_pair_gen(p, q, g):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    L = (p.bit_length() + 1, p.bit_length())[p.bit_length() % 2 == 0]
    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]

    if (L, N) not in acceptable_values:
        return "ERROR", (0, 0)

    c = secrets.randbits(N + 64)
    x = (c % (q - 1)) + 1
    y = fast_modular_expn(g, x, p)

    return "SUCCESS", (x, y)

# Generating of per-message secret numbers
def gen_secret_num(p, q, g):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    L = (p.bit_length() + 1, p.bit_length())[p.bit_length() % 2 == 0]
    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]

    if (L, N) not in acceptable_values:
        return "ERROR", (0, 0)

    c = secrets.randbits(N + 64)
    k = (c % (q - 1)) + 1
    inv_k = pow(k, q - 2, q)
    return "SUCCESS", (k, inv_k)

# DSA signing procedure
def dsa_sign(p, q, g, key_pair, M):
    '''
        DSA signing procedure using hardcoded message
        Academic implementation to test only purposes
    '''

    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]

    hash_M = hashlib.sha256(M.encode()).hexdigest()
    leftmost_bits = min(N, outlen) // 4

    while True:
        status, secret_nums = gen_secret_num(p, q, g)
        print("GENERATE secret number. Status = {}".format(status))

        r = fast_modular_expn(g, secret_nums[0], p) % q
        z = int(hash_M[0:leftmost_bits], 16)
        s = (secret_nums[1] * (z + key_pair[0] * r)) % q

        if r != 0 and s != 0:
            break

    signature = (r, s)

    return "SUCCESS", signature, M

def dsa_sign_verification(p, q, g, signature, M, key_pair):
    N = (q.bit_length() + 1, q.bit_length())[q.bit_length() % 2 == 0]

    # Check parameters
    if not (1 < signature[0] < q):
        return "SIGNATURE INVALID"

    if not (1 < signature[1] < q):
        return "SIGNATURE INVALID"

    hash_M = hashlib.sha256(M.encode()).hexdigest()
    leftmost_bits = min(N, outlen) // 4

    w = pow(signature[1], q - 2, q)
    z = int(hash_M[0:leftmost_bits], 16)
    u1 = (z * w) % q
    u2 = (signature[0] * w) % q
    v = (((pow(g, u1, p)) * (pow(key_pair[1], u2, p))) % p ) % q

    # Verification
    if v == signature[0]:
        return "SIGNATURE VERIFIED"
    return "SIGNATURE INVALID"

# DSA Signature Validation
def dsa_signature_validation(l_bits, n_bits):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    M = "Something to test the DSA algorithm"

    if (l_bits, n_bits) not in acceptable_values:
        print ("INVALID L AND N")

    status, firstseed = first_seed(n_bits)
    print("GENERATE firsteed. Status = {}".format(status))
    status, p,q, pseed, qseed, pgen_counter, qgen_counter = constructive_prime_gen(l_bits, n_bits, firstseed)
    print("GENERATE p and q. Status = {}".format(status))
    status = validation_pq_st(p, q, [firstseed, pseed, qseed], pgen_counter, qgen_counter)
    print("VALIDATION OF p AND q. Status = {}".format(status))
    domain_parameter_seed = int(str(firstseed) + str(pseed) + str(qseed))
    g = verif_gen_g(p, q, domain_parameter_seed)
    status = (g, "SUCCESS")[g != "INVALID"]
    print("GENERATE g. Status = {}".format(status))
    status = g_validation(p, q, domain_parameter_seed, g)
    print("VALIDATION OF g. Status = {}".format(status))
    status, key_pair = key_pair_gen(p, q, g)
    print("GENERATE key pair. Status = {}".format(status))
    status, signature, message = dsa_sign(p, q, g, key_pair, M)
    print("GENERATE signature. Status = {}".format(status))
    status = dsa_sign_verification(p, q, g, signature, M, key_pair)
    print("DSA SIGNATURE\n{}\nOF MESSAGE\n{}\nVERIFICATION PROCES. Status = {}".format(signature, M, status))

# Main function with getopt arguments
def main(argv):
    l_bits = -1
    n_bits = -1

    try:
        opts, args = getopt.getopt(argv,"hl:n:",["L=","N="])
    except getopt.GetoptError:
        print ('dsa.py -l L -n N')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('dsa.py -l L -n N')
            sys.exit()
        elif opt in ("-l", "--Lbits"):
            l_bits = int(arg)
        elif opt in ("-n", "--Nbits"):
            n_bits = int(arg)

    signature_validation = dsa_signature_validation(l_bits, n_bits)

# Standard main call
if __name__ == '__main__':
      # execute only if run as a script
      main(sys.argv[1:])
