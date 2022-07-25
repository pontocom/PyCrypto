import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def do_encryption_stuff():
    input_message = input("Message to cipher: ")
    message = input_message.encode('ascii')
    do_encrypt_with_passphrase(message)
    do_encrypt_with_sk(message)


def do_encrypt_with_passphrase(message):
    print("\nEncrypting with a passphrase (derived to a 256-bit secret key using PBKDF2)")
    input_passphrase = input("Enter a passphrase: ")

    passphrase = input_passphrase.encode('ascii')

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    print("KEY = " + str(key))
    f = Fernet(key)
    ciphertext = f.encrypt(message)
    plaintext = f.decrypt(ciphertext)
    print("Ciphertext = " + str(ciphertext))
    print("Plaintext = " + str(plaintext))


def do_encrypt_with_sk(message):
    key = os.urandom(32)
    iv = os.urandom(16)
    nonce = os.urandom(16)
    do_aes(message, 'ECB', key, iv, nonce)
    do_aes(message, 'CBC', key, iv, nonce)
    do_aes(message, 'OFB', key, iv, nonce)
    do_aes(message, 'CFB', key, iv, nonce)
    do_aes(message, 'CTR', key, iv, nonce)
    do_chacha20(message, key, nonce)
    do_camellia(message, key, iv)


# Encrypt with AES, using multiple modes
def do_aes(message, mode, key, iv=None, nonce=None):
    print("\nEncrypting with AES, 256-bit key, mode " + mode)

    print("Data:" + str(message))

    # AES works on blocks of 128bits (32 bytes) so we need to make user the message is multiple of the block lenght
    if len(message) % 16 != 0:
        # handling the padding of the messages
        padder = padding.PKCS7(128).padder()
        paddeddata = padder.update(message)
        paddeddata += padder.finalize()
        print("Data (padded):" +  str(paddeddata))
        message = paddeddata

    print("KEY = " + str(base64.b64encode(key)))
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    if mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    if mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    if mode == 'CTR':
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(plaintext)
    plaintext_data = data + unpadder.finalize()

    print("Plaintext = " + str(plaintext_data))


# Encrypt with ChaCha20
def do_chacha20(message, key, nonce):
    print("\nEncrypting with ChaCha20")
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    ciphertext = encryptor.update(message)
    plaintext = decryptor.update(ciphertext)
    print("KEY = " + str(base64.b64encode(key)))
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))
    print("Plaintext = " + str(plaintext))


# Encrypt with Camellia
def do_camellia(message, key, iv):
    print("\nEncrypting with Camellia")
    print("Data:" + str(message))

    # Camellia works on blocks of 128bits (32 bytes) so we need to make user the message is multiple of the block lenght
    if len(message) % 16 != 0:
        # handling the padding of the messages
        padder = padding.PKCS7(128).padder()
        paddeddata = padder.update(message)
        paddeddata += padder.finalize()
        print("Data (padded):" +  str(paddeddata))
        message = paddeddata

    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    ciphertext = encryptor.update(message)
    plaintext = decryptor.update(ciphertext)
    print("KEY = " + str(base64.b64encode(key)))
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(plaintext)
    plaintext_data = data + unpadder.finalize()

    print("Plaintext = " + str(plaintext_data))

