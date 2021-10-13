from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


# Create a new keypair
def create_key_pair(keysize):
    print("\nCreating a new key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=keysize)
    return private_key


# Print the key pair components
def print_key(privkey):
    pem_privkey = privkey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    for pemprivkey in pem_privkey.splitlines():
        print(pemprivkey)

    pubkey = privkey.public_key()
    pem_pubkey = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    for pempubkey in pem_pubkey.splitlines():
        print(pempubkey)


# Returns the public key
def get_public_key(privkey):
    return privkey.public_key()


# Ciphers a message with the public key
def cipher_with_public_key(message, pubkey):
    print("\nCiphering with the public key...")

    ciphertext = pubkey.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Ciphertext = " + str(ciphertext))
    return ciphertext


# Decipher a plaintext with the private key
def decipher_with_private_key(privkey, ciphertext):
    print("\nDeciphering with the private key...")
    plaintext = privkey.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Plaintext = " + str(plaintext.decode()))


# Do the encryption stuff with the public key cryptography
def do_encryption_stuff():
    privkey = create_key_pair(4096)
    print_key(privkey)

    input_message = input("Message to cipher: ")
    message = input_message.encode('ascii')

    ciphertext = cipher_with_public_key(message, get_public_key(privkey))
    decipher_with_private_key(privkey, ciphertext)
    return
