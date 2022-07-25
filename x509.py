import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def print_x509_menu():
    print("-------------------------")
    print("|     X.509 M e n u     |")
    print("-------------------------")
    print("[1] Create Key Pair")
    print("[2] Create CSR")
    print("[3] Create Self Signed Certificate")
    print("[0] Exit")


def create_key_pair():
    input_keysize = input("Enter the keysize: ")
    input_password = input("Enter the password to protect the private key: ")
    print("Creating a key pair... this may take some time...")

    key = rsa.generate_private_key(public_exponent=65537, key_size=int(input_keysize))
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(input_password.encode('ascii')),))


def read_key_pair():
    input_password = input("Enter the password to access the private key: ")
    with open("key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=input_password.encode('ascii'))

    return private_key


def do_x509_stuff():
    while True:
        print_x509_menu()
        option = input("Enter option -> ")

        if option == '1':
            create_key_pair()
        elif option == '2':
            privkey = read_key_pair()
            create_CSR(privkey)
        elif option == '3':
            privkey = read_key_pair()
            create_self_signed_certificate(privkey)
        elif option == '0':
            break
        else:
            print("Wrong option selected!!!")
    return False


def create_CSR(key):
    print("To create the CSR we need to collect some data. Please enter it bellow:")
    country_name = input("Country Name: ")
    state_or_province_name = input("State or Province Name: ")
    locality_name = input("Locality Name: ")
    organization_name = input("Organization Name: ")
    common_name = input("Common Name: ")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Details to be contained in the certificate
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Alternative names for common name
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
        ]),
        critical=False,
    # Sign the CSR with our private key
    ).sign(key, hashes.SHA256())
    # write the CSR to disk
    with open("csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def create_self_signed_certificate(key):
    print("Creating a self-signed certificate...")
    print("To do this we need to collect some data. Please enter it bellow:")
    country_name = input("Country Name: ")
    state_or_province_name = input("State or Province Name: ")
    locality_name = input("Locality Name: ")
    organization_name = input("Organization Name: ")
    common_name = input("Common Name: ")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 10 years in duration
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost")
        ]),
        critical=False
    # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open("root_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

