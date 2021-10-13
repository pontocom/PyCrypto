from cryptography.hazmat.primitives import hashes


#Computes different types of hashes from the user input
def do_hashes(message):
    md5 = hashes.Hash(hashes.MD5())
    md5.update(message)
    md5_hash = md5.finalize()

    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(message)
    sha1_hash = sha1.finalize()

    sha256 = hashes.Hash(hashes.SHA256())
    sha256.update(message)
    sha256_hash = sha256.finalize()

    sha512 = hashes.Hash(hashes.SHA512())
    sha512.update(message)
    sha512_hash = sha512.finalize()

    print('MD5    = ' + md5_hash.hex())
    print('SHA1   = ' + sha1_hash.hex())
    print('SHA256 = ' + sha256_hash.hex())
    print('SHA512 = ' + sha512_hash.hex())


#Reads the input message from the user
def read_message():
    input_msg = input('[Please enter the message] -> ')
    message = input_msg.encode('ascii')
    return message

