import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
import pk_encryption as pk


# Sign a message with a private key
def sign_with_private_key(privkey, message):
    print("\nSigning message with the private key...")
    signature = privkey.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    print("Signature = " + str(base64.b64encode(signature)))
    return signature


# Verify a signed message and check for the signature validity
def verify_with_public_key(pubkey, message, signature):
    print("\nVerifying message with the public key...")
    try:
        verification = pubkey.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Signature is VALID!")
    except InvalidSignature:
        print("Signature is INVALID!")


# Execute all the different digital signatures stuff
def do_digital_signature_stuff():
    privkey = pk.create_key_pair(4096)

    input_message = input("Message to sign: ")
    message = input_message.encode('ascii')

    signature = sign_with_private_key(privkey, message)
    verify_with_public_key(pk.get_public_key(privkey), message, signature)

