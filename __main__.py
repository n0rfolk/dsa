import sys, getopt

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
    print l_bits, n_bits

if __name__ == '__main__':
      # execute only if run as a script
      main(sys.argv[1:])
