import os
import base64
from cryptography.hazmat.primitives import hashes, hmac, cmac
from cryptography.hazmat.primitives.ciphers import algorithms


#Cipher-based message authentication code (CMAC)
def do_cmac(message, key):
    print("\nCipher-based message authentication code (CMAC)")
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message)
    signature = c.finalize()
    print("CMAC : " + str(base64.b64encode(signature)))


#Hash-based message authentication codes (HMAC)
def do_hmac(message, key):
    print("\nHash-based message authentication codes (HMAC)")
    h = hmac.HMAC(key, hashes.SHA512())
    h.update(message)
    signature = h.finalize()
    print("HMAC : " + str(base64.b64encode(signature)))


def do_mac():
    print("\nEnter a message to create the MAC from")
    input_passphrase = input("Message: ")

    message = input_passphrase.encode('ascii')
    key = os.urandom(32)

    do_hmac(message, key)
    do_cmac(message, key)
