#!/usr/bin/python3
 #-*- coding=utf-8 -*-
from Crypto.Cipher import AES
from Crypto import Random
from PIL import Image
import numpy as np
import io
import sys

Key = b'Sixteen byte key'   # Key
# IV = Random.new().read(AES.block_size) # IV
IV = b'5\x8dh\xce\xb9\x8b\xaa\xb4\xae\xefOK\xb5v\x9e\xcc' # Random IV
output_filename = "./encrypt_result.bmp"    # output image filename

def byte_xor(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])

def ECB_Mode(key, plaintext):

    cipher = AES.new(key, AES.MODE_ECB)     # AES block cipher
    ciphertext = bytes()
    
    for i in range(0,len(plaintext),AES.block_size):
        # take one block size
        block = plaintext[i:i+AES.block_size]
        
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block) # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])
        
        # encrypt
        ciphertext += cipher.encrypt(block)
    return ciphertext


def CBC_Mode(key, plaintext, IV):

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = bytes()
    encrypted = IV      # pre-cipher block

    for i in range(0,len(plaintext),AES.block_size):
        # take one block size
        block = plaintext[i:i+AES.block_size]
        
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block)   # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])

        # encrypt
        encrypted = cipher.encrypt(byte_xor(block, encrypted))   # equal to current cipher block
        ciphertext += encrypted
    return ciphertext

def Cool_PCBC_Mode(key,plaintext,IV):
    cipher = AES.new(key,AES.MODE_ECB)
    ciphertext = bytes()
    encrypted = IV

    for i in range(0,len(plaintext),AES.block_size):
        # take one block size
        block = plaintext[i:i+AES.block_size]
        
        # padding if len of the last temp not enough
        if(len(block) != AES.block_size):
            padding = AES.block_size - len(block)   # used number of empty bytes to padding
            for p in range(padding):
                block += bytes([padding])
        
        # encrypt
        encrypted = cipher.encrypt(byte_xor(block,encrypted))
        ciphertext += encrypted
        encrypted = byte_xor(encrypted,block)
    return ciphertext

# PPM to Byte array
def PPM_to_ByteArr(open_file):
    im = Image.open(open_file)  # read image
    imgByteArr = io.BytesIO()
    im.save(imgByteArr, format='PPM')   # save image as PPM format to imgByteArr
    imgByteArr = imgByteArr.getvalue()
    return imgByteArr

def Preprocess(open_file):
    imgByteArr = PPM_to_ByteArr(open_file)   # Read image and transfer PPM to Byte array

    Header = imgByteArr[0:15]   # 3 header information
    Plaintext = imgByteArr[15:] # plaintest not include header
    return imgByteArr,Header,Plaintext

def Output_image(Header, Ciphertext, output_name):
    # Cipher to image
    Ciphertext = Header + Ciphertext
    img = Image.open(io.BytesIO(Ciphertext))
    img.save(output_name)
    # show image
    img.show(output_name)

def main():
    # Input format
    if len(sys.argv) != 2:
        print("[Warning]")
        print("  Input format:  python3 <filename> <Mode>")
        print("  <Mode>:  ECB  CBC  PCBC")
        return
    else:
        Mode = sys.argv[1].upper()
        pass
    
    # Initial
    open_file = "./linux-penguin.jpg"
    # open_file = "./fatdog.jpg"
    imgByteArr,Header,Plaintext = Preprocess(open_file)

    # Call Mode
    if Mode == "ECB":
        Ciphertext = ECB_Mode(Key,Plaintext)
    elif Mode == "CBC":
        Ciphertext = CBC_Mode(Key,Plaintext,IV)
    elif Mode == "PCBC":
        Ciphertext = Cool_PCBC_Mode(Key,Plaintext,IV)
        pass
    else:
        print("[Warning]  Undefined Mode")
        print("Mode:  ECB  CBC  PCBC")
        return

    
    # Ciphertext to output image
    Output_image(Header, Ciphertext, output_filename)


if __name__ == '__main__':
    # main func
    print('test')
    #main()
