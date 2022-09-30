import sys
import binascii

def main(argv):
    if (len(argv)):
        with open(argv[0],'rb') as f:
            file_bytes = f.read()         
        val = 0
        for b in file_bytes:
            print('0x{:02x}'.format(b ^ val), end=",")
            val+=1
            if (val % 16)==0:
                print("")
            if val==256:
                val=0


    else:
        print("Must supply public key filename")

if __name__ == "__main__":
   main(sys.argv[1:])
