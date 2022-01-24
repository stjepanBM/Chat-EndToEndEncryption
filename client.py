import socket
import os
import threading
import hashlib
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import signal
from lazyme.string import color_print

def RemovePadding(s):
    return s.replace(b'`', b'')


def Padding(s):
    return s + ((16 - len(s) % 16) * '`')


def GenerateKeys():
    random = Random.new().read
    RSAkey = RSA.generate(3072, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()

    try:
        with open('private.txt', 'w') as src:
            src.write(private.decode('utf-8'))

        with open('public.txt', "w") as src:
            src.write(public.decode('utf-8'))

    except FileNotFoundError as e:
        print(e)

    return public, private

def encrypt_key(key, msg):
    try:

            encryptor = PKCS1_OAEP.new(key)
            encrypted = encryptor.encrypt(msg)

            return encrypted.hex()
    except FileNotFoundError as e:
        print(e)


def ReceiveMessage():
    while True:
        emsg = server.recv(1024)
        msg = RemovePadding(AESKey.decrypt(emsg))
        if msg == FLAG_QUIT:
            color_print("\n[!] Server was shutdown by admin", color="red", underline=True)
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Server's encrypted message \n" + emsg.decode(), color="gray")
            print("\n[!] SERVER SAID : ", msg)


def SendMessage():
    while True:
        msg = input("[>] Your message")
        en = AESKey.encrypt(Padding(msg))
        server.send(str(en))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Your encrypted message \n" + en.decode(), color="gray")


if __name__ == "__main__":
    #objects
    server = ""
    AESKey = ""
    FLAG_READY = b"Ready"
    FLAG_QUIT = "quit"
    # 10.1.236.227
    # public key and private key
    public, private = GenerateKeys()

    tmpPub = hashlib.sha512(public)
    my_hash_public = tmpPub.hexdigest()

    print(public)
    print("\n", private)

    host = '127.0.0.1'
    port = 5599

    check = False

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))
        check = True
    except BaseException as e:
        color_print("\n[!] Check Server Address or Port", color="red", underline=True)

    if check is True:
        color_print("\n[!] Connection Successful", color="green", bold=True)
        server.send(public + b":" + my_hash_public.encode())
        # receive server public key,hash of public,eight byte and hash of eight byte

        server_string = server.recv(2048)
        split = server_string.split(b"rascipaj")
        toDecrypt = split[0]
        serverPublic = split[1]
        color_print("\n[!] Server's public key\n", color="blue")
        print(serverPublic)
        priv = RSA.importKey(private)
        priv = PKCS1_OAEP.new(priv)
        #bytes.fromhex(toDecrypt.decode().replace("\r\n", '')))

        decrypted = priv.decrypt(toDecrypt)
        #decrypted = decrypted.decode().replace("\r\n", '')
        splittedDecrypt = decrypted.split(b":")
        eightByte = splittedDecrypt[0]
        hashOfEight = splittedDecrypt[1]
        hashOfSPublic = splittedDecrypt[2]
        color_print("\n[!] Client's Eight byte key in hash\n", color="blue")
        print(hashOfEight)

        sess = hashlib.sha512(eightByte)
        session = sess.hexdigest()

        hashObj = hashlib.sha512(serverPublic)
        server_public_hash = hashObj.hexdigest()
        color_print("\n[!] Matching server's public key & eight byte key\n", color="blue")
        if server_public_hash == hashOfSPublic.decode() and session == hashOfEight.decode():
            # encrypt back the eight byte key with the server public key and send it
            color_print("\n[!] Sending encrypted session key\n", color="blue")
            serverpublicKey = RSA.importKey(serverPublic)
            serverpublicKey = PKCS1_OAEP.new(serverpublicKey)
            encrypted_serverPublic = serverpublicKey.encrypt(eightByte)
            server.send(encrypted_serverPublic)

            color_print("\n[!] Creating AES key\n", color="blue")
            key_128 = eightByte + eightByte[::-1]
            AESKey = AES.new(key_128, AES.MODE_CBC, IV=key_128)
            serverMessage = server.recv(2048)
            serverMsg = RemovePadding(AESKey.decrypt(serverMessage))
            if serverMsg == FLAG_READY:
                color_print("\n[!] Server is ready to communicate\n", color="blue")
                serverMsg = input("\n[>]Enter your name: ")
                server.send(serverMsg.encode())
                threading_rec = threading.Thread(target=ReceiveMessage())
                threading_rec.start()
                threading_send = threading.Thread(target=SendMessage())
            else:
                color_print("\nServer (Public key && Public key hash) || (Session key && Hash of Session key) doesn't match", color="red", underline=True)

        else:
            color_print("\nPUKLO",color="red", underline=True)