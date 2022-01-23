import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

n_bits = 3072

def generate_keys(bits):

    keyPair = RSA.generate(bits)

    pubKey = keyPair.public_key()
    pubKeyPEM = pubKey.exportKey()
    #print(pubKeyPEM.decode('ascii'))

    privKeyPEM = keyPair.exportKey()
    #print(privKeyPEM.decode('ascii'))

    with open("keys/private_key.pem", "w") as src:
        src.write(privKeyPEM.decode('utf-8'))

    with open("keys/public_key.txt", "w") as out:
        out.write(pubKey.exportKey().decode('utf-8'))

    return privKeyPEM, pubKeyPEM

def encrypt_document(msg):
    with open("keys/public_key.txt", "rb") as src:
        public_key = RSA.importKey(src.read())

    try:
        with open(msg) as f:
            buf = f.read()
            encryptor = PKCS1_OAEP.new(public_key)
            encrypted = encryptor.encrypt(buf.encode())

            with open(f"files/encrypted_{encrypted.hex()[0:3]}", "w") as src:
                src.write(encrypted.hex())

            print("Encrypted: ")
            print(encrypted.hex())
            return encrypted.hex()
    except FileNotFoundError as e:
        print(e)

def encrypt_folder(recursive_option, path):
    for root, dirs, files in os.walk(path, topdown=True):

        if menu03_options[recursive_option] == "Non-recursive":
            while len(dirs) > 0:
                dirs.pop()
            for name in files:
               encrypt_document(os.path.join(root, name))

        if menu03_options[recursive_option] == "Recursive":
            print(root)
            for name in files:
               encrypt_document(os.path.join(root, name))

def decrypt_folder(recursive_option, path):
    for root, dirs, files in os.walk(path, topdown=True):

        if menu03_options[recursive_option] == "Non-recursive":
            while len(dirs) > 0:
                dirs.pop()
            print(root)
            for name in files:
                print(decrypt_document(os.path.join(root, name)))

        if menu03_options[recursive_option] == "Recursive":
            print(root)
            for name in files:
                print(f"File: {name}")
                print(decrypt_document(os.path.join(root, name)))


def decrypt_document(msg):
    with open("keys/private_key.pem", "r") as src:
        private = RSA.importKey(src.read())

    with open(msg, "r") as red:
        mess = red.read()

    decryptor = PKCS1_OAEP.new(private)
    try:
        decrypted = decryptor.decrypt(bytes.fromhex(mess))
    except ValueError as r:
        return r
    return decrypted

menu01_options = {
    1: "Exit program",
    2: "Generate a public/private key",
    3: "Encrypt file",
    4: "Decrypt file",
}
menu02_options = {
    1: "Single file",
    2: "Content of a folder",
}

menu03_options = {
    1: "Recursive",
    2: "Non-recursive",
}


def print_menu01():
    for key in menu01_options.keys():
        print(key, '--', menu01_options[key])


def print_menu02():
    for key in menu02_options.keys():
        print(key, '---', menu02_options[key])


def print_menu03():
    for key in menu03_options.keys():
        print(key, '---', menu03_options[key])


while True:
    print_menu01()
    option = int(input("Enter choice:"))
    if option == 1:
        exit()
    elif option == 2:
        try:
            prv, pub = generate_keys(n_bits)
            print("Keys are generated succesfully! Public key available in keys/public_key.txt")
        except ValueError as err:
            print("Problem with generation of keys!")
    elif option == 3:
        print_menu02()
        sign_option = int(input("Enter choice of what do you want to sign: "))

        if sign_option == 2:
            print_menu03()
            recursive_option = int(input("Enter your choice of method: "))
            folder_path = input("Enter path of the folder you want to hash files from: ")
            encrypt_folder(recursive_option, folder_path)
        else:
            path = input("Enter path of the file: ")
            encrypt_document(path)

    elif option == 4:
        print_menu02()
        sign_option = int(input("Enter choice of what do you want to sign: "))

        if sign_option == 2:
            print_menu03()
            recursive_option = int(input("Enter your choice of method: "))
            folder_path = input("Enter path of the folder you want to hash files from: ")
            decrypt_folder(recursive_option, folder_path)
        else:
            path = input("Enter path of the file: ")
            decr = decrypt_document(path)
            print(decr)







