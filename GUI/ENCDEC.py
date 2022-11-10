import binascii
import os
import time
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from secretsharing import PlaintextToHexSecretSharer
from secretsharing import SecretSharer

def shamirs_split(file_object):
	text = file_object.read()
	list = PlaintextToHexSecretSharer.split_secret(text,2,2)
	hexcode = SecretSharer.split_secret(list[0][2:],2,2);
	return hexcode,list[1]

def shamirs_join(list,str):
	temp = []
	msg_alpha =  SecretSharer.recover_secret(list[0:2])
	msg_alpha = '1-'+msg_alpha
	temp.append(msg_alpha)
	temp.append(str)
	text = PlaintextToHexSecretSharer.recover_secret(temp[0:2])
	return text

class AESCipher(object):
    BS = 16

    def __init__(self, key):
        self.key = key
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS).encode()
        self.unpad = lambda s: s[:-ord(s[len(s)-1:])]

    @staticmethod
    def iv():
        return chr(0) * 16

    def encrypt(self, message):
        raw = self.pad(message)
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, self.iv().encode('utf-8'))
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, self.iv().encode('utf-8'))
        dec = cipher.decrypt(enc)
        return self.unpad(dec).decode('utf-8')



