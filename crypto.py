import hashes as h
import sk_encryption as sk
import mac as m
import pk_encryption as pk
import digital_signature as ds
import x509 as x


def print_menu():
    print("-------------------")
    print("|     M e n u     |")
    print("-------------------")
    print("[1] Compute Hash")
    print("[2] Secret-key encryption")
    print("[3] Compute Message Authentication Code")
    print("[4] Public-key encryption")
    print("[5] Digital signatures")
    print("[6] X.509 certificates")
    print("[0] Exit")


def compute_hashes():
    message = h.read_message()
    h.do_hashes(message)
    return


def compute_sk_encryption():
    sk.do_encryption_stuff()
    return


def compute_mac():
    m.do_mac()
    return


def compute_pk_encryption():
    pk.do_encryption_stuff()
    return


def compute_digital_signature():
    ds.do_digital_signature_stuff()
    return


def compute_x509_certificates():
    x.do_x509_stuff()
    return


if __name__ == "__main__":
    while True:
        print_menu()
        option = input("Enter option -> ")

        if option == '1':
            compute_hashes()
        elif option == '2':
            compute_sk_encryption()
        elif option == '3':
            compute_mac()
        elif option == '4':
            compute_pk_encryption()
        elif option == '5':
            compute_digital_signature()
        elif option == '6':
            compute_x509_certificates()
        elif option == '0':
            break
        else:
            print("Wrong option selected!!!")
