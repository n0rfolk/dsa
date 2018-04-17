import sys, getopt, secrets

'''
DSA - Digital Signature Algorithm
@author = n0rfolk

L = 1024, N = 160
L = 2048, N = 224
L = 2048, N = 256
L = 3072, N = 256
'''
# Generating p and q using Shawe-Taylor Algorithm
def first_seed(N, seedlen=256):
    status = 'FAILURE'
    firstseed = 0

    if(seedlen < N):
        return status, firstseed

    while firstseed < pow(2, N - 1):
        firstseed = secrets.randbits(seedlen)

    return firstseed

def primes_generator(l_bits=1024, n_bits=160):
    acceptable_values = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    p = -1
    q = -1

    if (l_bits, n_bits) not in acceptable_values:
        return p,q

    
    return p,q

def dsa_signature_validation(l_bits, n_bits):
    p,q = primes_generator(l_bits, n_bits)
    if(p == -1 or q == -1):
        return 'INVALID'

def main(argv):
    l_bits = -1
    n_bits = -1
    try:
        opts, args = getopt.getopt(argv,"hl:n:",["L=","N="])
    except getopt.GetoptError:
        print 'dsa.py -l L -n N'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'dsa.py -l L -n N'
            sys.exit()
        elif opt in ("-l", "--Lbits"):
            l_bits = arg
        elif opt in ("-n", "--Nbits"):
            n_bits = arg
    #print l_bits, n_bits
    signature_validation = dsa_signature_validation(l_bits, n_bits)

if __name__ == '__main__':
      # execute only if run as a script
      main(sys.argv[1:])
