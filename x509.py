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
    print("[2] Create Self Signed Certificate")
    print("[3] Create CSR")
    print("[4] Load CSR and Issue Certificate")
    print("[0] Exit")


def create_key_pair(filename):
    input_keysize = input("Enter the keysize: ")
    input_password = input("Enter the password to protect the private key: ")
    print("Creating a key pair... this may take some time...")

    key = rsa.generate_private_key(public_exponent=65537, key_size=int(input_keysize))
    with open(filename, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(input_password.encode('ascii')),))


def read_key_pair(filename):
    input_password = input("Enter the password to access the private key: ")
    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=input_password.encode('ascii'))

    return private_key


def read_csr(filename):
    with open(filename, "rb") as f:
        csr = f.read()
    return csr


def read_crt(filename):
    with open(filename, "rb") as f:
        cert = f.read()
    return cert


def do_x509_stuff():
    while True:
        print_x509_menu()
        option = input("Enter option -> ")

        if option == '1':
            create_key_pair("ca.key")
        elif option == '2':
            privkey = read_key_pair("ca.key")
            create_self_signed_certificate(privkey)
        elif option == '3':
            create_key_pair("user.key")
            privkey = read_key_pair("user.key")
            create_CSR(privkey)
        elif option == '4':
            privkey = read_key_pair("ca.key")
            cert = read_crt("root_certificate.pem")
            csr = read_csr("user.csr")
            load_csr_and_issue_certificate(privkey, cert, csr)
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
    with open("user.csr", "wb") as f:
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
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False),
        critical=True
    # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open("root_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_csr_and_issue_certificate(key, cert, csr):
    x509_ca_cert = x509.load_pem_x509_certificate(cert)

    x509_csr = x509.load_pem_x509_csr(csr)
    if x509_csr.is_signature_valid:
        print("CSR signature is valid!!!")
    else:
        print("CSR signature is invalid!!!")
        return False

    s_cn = x509_csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    s_st = x509_csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    s_ln = x509_csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    s_on = x509_csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    s_c = x509_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    s_publickey = x509_csr.public_key()

    i_cn = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    i_st = x509_ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    i_ln = x509_ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    i_on = x509_ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    i_c = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    print("CSR information")
    print("Country Name: " + s_cn)
    print("State or Province Name: " + s_st)
    print("Locality Name: " + s_ln)
    print("Organization Name: " + s_on)
    print("Common Name: " + s_c)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, s_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, s_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, s_on),
        x509.NameAttribute(NameOID.COMMON_NAME, s_c),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, i_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, i_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, i_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, i_on),
        x509.NameAttribute(NameOID.COMMON_NAME, i_c),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        s_publickey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 1 year in duration
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False,
                      content_commitment=False, data_encipherment=True, key_agreement=True, encipher_only=False,
                      decipher_only=False),
        critical=True
        # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open("user.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return True
