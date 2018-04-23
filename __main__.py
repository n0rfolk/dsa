import sys, getopt, secrets, hashlib, sympy, math

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
            x = x + (hash(prime_seed + i) * pow(2, i * outlen))
        prime_seed = prime_seed + iterations + 1
        x = pow(2, length - 1) + x % pow(2, length - 1)
        t = math.ceil(x/(2 * c_0))

        while True:
            if (2 * t * c_0 + 1 > pow(2, length)):
                t = math.ceil((pow(2, length - 1))/(2 * c_0))
            c = 2 * t * c_0 + 1
            prime_gen_counter = prime_gen_counter + 1
            a = 0
            for i in range(iterations):
                a = a + (hash(prime_seed + i) * pow(2, i * outlen))
            prime_seed = prime_seed + iterations + 1
            a = 2 + (a % (c - 3))
            z = pow(a, 2 * t) % c

            if (1 == math.gcd(z - 1, c)) and (1 == fast_modular_expn(z, c_0, c)):
                prime = c
                return 'SUCCESS', prime, prime_seed, prime_gen_counter

            if (prime_gen_counter >= 4 * length + old_counter):
                return 'FAILURE', 0, 0, 0

            t += 1

    prime_seed = input_seed
    prime_gen_counter = 0

    while True:
        c = hash(prime_seed)^hash(prime_seed + 1)
        c = pow(2, length - 1) + (c % pow(2, length - 1))
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

    while firstseed < pow(2, N - 1):
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
        x += hash(pseed + i) * pow(2, i * outlen)
    pseed += iterations + 1
    x = pow(2, L - 1) + x % pow(2, L - 1)

    t = math.ceil(x/(2 * q * p_0))

    while True:
        if 2 * t * q * p_0 + 1 > pow(2, L):
            t = math.ceil((pow(2, L - 1))/(2 * q * p_0))
        p = 2 * t * q * p_0 + 1
        pgen_counter += 1

        a = 0
        for i in range(iterations):
            a += hash(pseed + i) * pow(2, i * outlen)
        pseed += iterations + 1
        a = 2 + a % (p - 3)
        z = (pow(a, 2 * t * q) % p)

        if (1 == math.gcd(z - 1, p)) and (1 == fast_modular_expn(z, p_0, p)):
            return 'SUCCESS', p, q, pseed, qseed, pgen_counter, qgen_counter

        if pgen_counter > 4 * L + old_counter:
            return -1, -1

        t += 1

def generation_pq_approved_hash(L, N, seedlen):
    '''
        Algorithm specification in Appendix A.1.1.2 in FIPS 186-4
    '''

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
    n = math.ceil(L / outlen) - 1
    b = L - 1 - (n * outlen)
    domain_parameter_seed = secrets.randbits(seedlen)
    U = hash(domain_parameter_seed) % pow(2, N - 1)
    q = pow(2, N - 1) + U + 1 - (U % 2)
    # TODO: Test primality of q with Appendix C.3
    # TODO: If q not a prime GOTO step 5
    offset = 1
    for counter in range(4L):
        for j in range(n):
            Vj = hash((domain_parameter_seed + offset + j) % pow(2, seedlen))
            # TODO: W parameter
            X = W + pow(2, L - 1)
            c = X % (2 * q)
            p = X - (c - 1)
            if p < pow(2, L - 1):
                offset = offset + n + 1
            # TODO: Test primality of p with Appendix C.3 if p is prime return p,q
            # TODO: step 12: GOTO step 5

    print (status)

# DSA Signature Validation
def dsa_signature_validation(l_bits, n_bits):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    if (l_bits, n_bits) not in acceptable_values:
        return 'INVALID'

    status, firstseed = first_seed(n_bits)

    p,q = constructive_prime_gen(l_bits, n_bits, firstseed)
    if(p == -1 or q == -1):
        return 'INVALID'

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

    #print (l_bits, n_bits)
    #signature_validation = dsa_signature_validation(l_bits, n_bits)
    #print (signature_validation)
    #print(st_random_prime(256, 0))
    print (generation_pq_approved_hash(1,1,1))

# Standard main call
if __name__ == '__main__':
      # execute only if run as a script
      main(sys.argv[1:])
