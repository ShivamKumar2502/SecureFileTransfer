import ENCDEC
import time
import unicodedata
import os
import os.path
import DH
import binascii
from numpy import long

global key
global prime_


def encrypt(filename,directory,public_key,private_key):
	key = DH.generate_secret(long(private_key), long(public_key))
	sai = key.encode("utf-8").hex()
	key = sai[0:32]
	file_obj = open(filename,"rb")
	t = time.time()
	msg1 = ENCDEC.AESCipher(key).encrypt(file_obj.read())
	s = time.time()
	#Exchange this with public key
	outputFilename = os.path.join(directory,"EncryptFile.txt")
	#outputFilename = os.path.join(directory,"EncodedFile.txt")
	file_obj = open(outputFilename,'w')
	file_obj.write(msg1)
	os.remove(filename)
	os.startfile(directory)


def decrypt(filename,directory,public_key,private_key):
	key = DH.generate_secret(long(private_key), long(public_key))
	str = key.encode("utf-8").hex()
	key = str[0:32]
	file_obj = open(filename,"rb")
	msg = file_obj.read()
	text = ENCDEC.AESCipher(key).decrypt(msg)
	outputFilename = os.path.join(directory,"NewDecodedFile.txt")
	file_obj = open(outputFilename,"w");
	file_obj.write(text)
	os.remove(filename)
	os.startfile(directory)

