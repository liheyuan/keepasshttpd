import base64
import random
from Crypto.Cipher import AES
import struct
from binascii import hexlify

AES_BLOCK_SIZE = 16

class AESObj:

    def __init__(self, key, iv):
        self.key = base64.b64decode(key)
        self.iv = base64.b64decode(iv)

    def get_key(self):
        return base64.b64encode(self.key)

    def encrypt(self, data):
        data = AESObj.pad(data)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(data))

    def decrypt(self, data):
        data = base64.b64decode(data)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return AESObj.unpad(cipher.decrypt(data))

    def verify(self, iv, verifier):
        return iv == self.decrypt(verifier)

    @staticmethod
    def gen_nonce():
        tmp = str(random.randint(1, 10 ** 16)).zfill(16)
        return base64.b64encode(tmp)

    @staticmethod
    def pad(s):
        n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
        return s + n * struct.pack('b', n)

    @staticmethod
    def unpad(data):
        extra = ord(data[-1])
        return data[:len(data)-extra]

