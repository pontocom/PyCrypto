from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509


def create_key_pair(keysize, keypassword):
    key = rsa.generate_private_key(public_exponent=65537, key_size=keysize)
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(keypassword),))


def do_x509_stuff():
    create_key_pair(4096, b'mypassword')
    return False

