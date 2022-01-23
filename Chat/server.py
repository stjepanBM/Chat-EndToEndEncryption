import socket
import os
import signal
import threading
import hashlib
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from lazyme.string import color_print



def RemovePadding(s):
    return s.replace('`','')


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

            return encrypted
    except FileNotFoundError as e:
        print(e)

def decrypt_key(key, msg):
    key_imp = RSA.importKey(key)

    try:
        decryptor = PKCS1_OAEP.new(key_imp)
        decrypted = decryptor.decrypt(bytes.fromhex(str(msg)))
    except ValueError as r:
        return r
    return decrypted


def ConnectionSetup():
    while True:
        if check is True:
            client, address = server.accept()
            color_print("\n[!] One client is trying to connect...", color="green", bold=True)

            clientPH = client.recv(2048)
            split = clientPH.split(":".encode())
            tmpClientPublic = split[0]
            clientPublicHash = split[1]
            color_print("\n[!] Anonymous client's public key\n", color="blue")
            print(tmpClientPublic)
            tmpClientPublic_rp = tmpClientPublic.decode().replace("\r\n", '')
            clientPublicHash_rp = clientPublicHash.decode().replace("\r\n", '')
            tmpHashObject = hashlib.sha512(tmpClientPublic_rp.encode())
            tmpHash = tmpHashObject.hexdigest()

        if tmpHash == clientPublicHash_rp:
                # sending public key,encrypted eight byte ,hash of eight byte and server public key hash
                color_print("\n[!] Anonymous client's public key and public key hash matched\n", color="blue")
                clientPublic = RSA.importKey(tmpClientPublic)
                fSend = eightByte + b":" + session.encode() + b":" + my_hash_public.encode()
                fSend_enc = encrypt_key(clientPublic, fSend)
                client.send(fSend_enc+ b":" + public)

                clientPH_new = client.recv(2048).decode()
                if clientPH_new != "":
                    clientPH_new = decrypt_key(private, clientPH)
                    color_print("\n[!] Matching session key\n", color="blue")
                    if clientPH_new == eightByte:
                        # creating 128 bits key with 16 bytes
                        color_print("\n[!] Creating AES key\n", color="blue")
                        key_128 = eightByte + eightByte[::-1]
                        AESKey = AES.new(key_128, AES.MODE_CBC, IV = key_128)
                        clientMsg = AESKey.encrypt(Padding(FLAG_READY))
                        client.send(clientMsg)
                        color_print("\n[!] Waiting for client's name\n", color="blue")

                        clientMsg = client.recv(2048)
                        CONNECTION_LIST.append((clientMsg, client))
                        color_print("\n" + clientMsg.decode() + " IS CONNECTED", color="green", underline=True)
                        threading_client = threading.Thread(target=broadcast_usr, args=[clientMsg, client, AESKey])
                        threading_client.start()
                        threading_message = threading.Thread(target=send_message, args=[client, AESKey])
                        threading_message.start()
                    else:
                        color_print("\nSession key from client does not match", color="red", underline=True)
        else:
            color_print("\nPublic key and public hash doesn't match", color="red", underline=True)
            client.close()


def send_message(socketClient, AESk):
    while True:
        msg = input("\n Enter your message: ")
        en = AESk.encrypt(Padding(msg))
        socketClient.send(str(en))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Your encrypted message \n" + en, color="gray")


def broadcast_usr(uname, socketClient, AESk):
    while True:
        try:
            data = socketClient.recv(1024)
            en = data
            if data:
                data = RemovePadding(AESk.decrypt(data))
                if data == FLAG_QUIT:
                    color_print("\n" + uname + " left the conversation", color="red", underline=True)
                else:
                    b_usr(socketClient, uname, data)
                    print("\n[!] ", uname, " SAID : ", data)
                    color_print("\n[!] Client's encrypted message\n" + en, color="gray")
        except Exception as x:
            print(x)
            break


def b_usr(cs_sock, sen_name, msg):
    for client in CONNECTION_LIST:
        if client[1] != cs_sock:
            client[1].send(sen_name)
            client[1].send(msg)


if __name__ == "__main__":
    # objects
    AESKey = ""
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    YES = "1"
    NO = "2"


    public, private = GenerateKeys()
    tmpPub = hashlib.sha512(public)
    my_hash_public = tmpPub.hexdigest()

    eightByte = os.urandom(8)
    sess = hashlib.sha512(eightByte)
    session = sess.hexdigest()

    check = False

    host = "127.0.0.1"
    port = 5599

    print(f"\n {public} \n {private}")
    color_print("\n[!] Eight byte session key in hash\n", color="blue")

    print(session)
    color_print("\n[!] Eight byte session key in hash\n", color="blue")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    color_print("\n[!] Server Connection Successful", color="green", bold=True)
    check = True
    threading_accept = threading.Thread(target=ConnectionSetup())
    threading_accept.start()



















