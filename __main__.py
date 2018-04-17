import sys, getopt, secrets, hashlib

'''
DSA - Digital Signature Algorithm
@author = n0rfolk
Based on publication FIPS 186-4
'''

# Chosen Hash() function SHA256, so outlen = 256
outlen = 256

#Primality test
def primality_test():
    status = False
    return status

# Generating p and q using Shawe-Taylor Algorithm
def hash(input):
    return hashlib.sha256(input).hexdigest()

def st_random_prime(length, input_seed):
    status = 'FAILURE'

    if length < 2:
        return status, 0, 0, 0

    if length >= 33:
        #TODO: step 14
        print('a')

    prime_seed = input_seed
    prime_gen_counter = 0

    c = hash(prime_seed)^hash(prime_seed + 1)
    c = pow(2, length - 1) + (c % pow(2, length - 1))
    c = (2 * int(c/2) + 1)

    prime_gen_counter += 1
    prime_seed += 2

    #TODO: primality test c
    if primality_test(c):
        prime = c
        return status, prime, prime_seed, prime_gen_counter

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

def constructive_prime_gen(L, N, firstseed):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    status = 'FAILURE'

    if (L, N) not in acceptable_values:
        return status

    return status, p, q, pseed, qseed, pgen_counter, qgen_counter

def dsa_signature_validation(l_bits, n_bits):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

    if (l_bits, n_bits) not in acceptable_values:
        return 'INVALID'

    status, firstseed = first_seed(n_bits)

    p,q = constructive_prime_gen(l_bits, n_bits, firstseed)
    if(p == -1 or q == -1):
        return 'INVALID'

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
    signature_validation = dsa_signature_validation(l_bits, n_bits)
    print (signature_validation)

if __name__ == '__main__':
      # execute only if run as a script
      main(sys.argv[1:])
