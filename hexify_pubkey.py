import sys
import binascii

def main(argv):
    if (len(argv)):
        with open(argv[0],'rb') as f:
            print(binascii.hexlify(f.read()))
    else:
        print("Must supply public key filename")

if __name__ == "__main__":
   main(sys.argv[1:])
