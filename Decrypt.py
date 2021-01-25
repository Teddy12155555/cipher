#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto import Random
from PIL import Image
import numpy as np
import io
import sys

# ----------------------------- #
import Encrypt as enc

# print('Key: ', enc.Key)   # Encrypt用的Key
# print('IV: ', enc.IV)     # Encrypt用的IV


def ECB_Mode(key, ciphertext):

    cipher = AES.new(key, AES.MODE_ECB)     # AES block cipher
    plaintext = bytes()
    
    for i in range(0,len(ciphertext),AES.block_size):
        # take one block size
        block = ciphertext[i:i+AES.block_size]
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block)   # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])

        # decrypt
        plaintext += cipher.decrypt(block)
    return plaintext


def CBC_Mode(key, ciphertext, IV):

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = bytes()
    iv = IV      # pre-cipher block

    for i in range(0,len(ciphertext),AES.block_size):
        # take one block size
        block = ciphertext[i:i+AES.block_size]
        
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block)   # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])

        # decrypt
        plaintext += enc.byte_xor(cipher.decrypt(block), iv)
        iv = block
    return plaintext

def Cool_PCBC_Mode(key,ciphertext,IV):

    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = bytes()
    decrypted = IV
    iv = IV
    
    for i in range(0,len(ciphertext),AES.block_size):
        # take one block size
        block = ciphertext[i:i+AES.block_size]
        
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block)   # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])
        
        # decrypt
        decrypted = enc.byte_xor(cipher.decrypt(block),iv)
        iv = enc.byte_xor(decrypted,block)
        plaintext += decrypted
    return plaintext


def main():
    # Input format
    if len(sys.argv) != 2:
        print("[Warning]")
        print("  Input format:  python3 <filename> <Mode>")
        print("  <Mode>:  ECB  CBC  Cool")
        return
    else:
        Mode = sys.argv[1].upper()
        pass
    
    # Initial
    open_file = enc.output_filename
    imgByteArr,Header,Ciphertext = enc.Preprocess(open_file)

    # Call Mode
    if Mode == "ECB":
        Plaintext = ECB_Mode(enc.Key,Ciphertext)
    elif Mode == "CBC":
        Plaintext = CBC_Mode(enc.Key, Ciphertext, enc.IV)
        pass
    elif Mode == "PCBC":
        Plaintext = Cool_PCBC_Mode(enc.Key, Ciphertext, enc.IV)
        pass
    else:
        print("[Warning]  Undefined Mode")
        print("Mode:  ECB  CBC  Cool")
        return

    # Ciphertext to output image
    enc.Output_image(Header, Plaintext, "./decrypt_reslut.gif")


if __name__ == '__main__':
    # main func
    main()
