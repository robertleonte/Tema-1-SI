#!/usr/bin/env python3

import socket

from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 65431
PORT_B = 65432
q = 5
K3 = b'0123456789123456'
cipher = AES.new(K3, AES.MODE_ECB)
f = open("plaintext.txt", "r")
counter = 1


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def padding(chunk):
    if len(chunk) < 16 and len(chunk) != 0:
        length = 16 - (len(chunk) % 16)
        chunk += bytes([length]) * length
    return chunk


def ofb_encrypt(input, chunk, cipher_to_use):
    crypted = cipher_to_use.encrypt(input)
    ciphertext = byte_xor(chunk, crypted)
    return ciphertext, crypted


def cbc_encrypt(input, chunk, cipher_to_use):
    xored = byte_xor(input, chunk)
    ciphertext = cipher_to_use.encrypt(xored)
    return ciphertext


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_client:
    s_client.bind((HOST, PORT_B))
    s_client.listen()
    print("I am listening")
    conn_client, addr_client = s_client.accept()
    print("Connected by", addr_client)
    end_of_file = False
    while True:
        if not end_of_file:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                while True:
                    request_of_enc = input("Type of encryption to be requested: ")
                    s.send(request_of_enc.encode())
                    if request_of_enc!="CBC" and request_of_enc!="OFB" and request_of_enc!="exit":
                        message = s.recv(1024).decode()
                        print(message)
                    else:
                        break
                response_key = s.recv(16)
                iv = s.recv(16)
            decrypted = cipher.decrypt(response_key)
            if request_of_enc != "exit":
                print("Cheia este", decrypted)

            counter_q = 0
            conn_client.send(request_of_enc.encode())
            if request_of_enc == "exit":
                break
            conn_client.send(response_key)
            conn_client.send(iv)
            cipher_main = AES.new(decrypted, AES.MODE_ECB)
            while counter_q < q:
                chunk = f.read(16).encode()
                chunk = padding(chunk)
                if not chunk:
                    end_of_file = True
                    break
                if counter == 1:
                    if request_of_enc == "OFB":
                        chunk_crypted, previous = ofb_encrypt(iv, chunk, cipher_main)
                    elif request_of_enc == "CBC":
                        chunk_crypted = cbc_encrypt(iv, chunk, cipher_main)
                        previous = chunk_crypted
                else:
                    if request_of_enc == "OFB":
                        chunk_crypted, previous = ofb_encrypt(previous, chunk, cipher_main)
                    elif request_of_enc == "CBC":
                        chunk_crypted = cbc_encrypt(previous, chunk, cipher_main)
                        previous = chunk_crypted
                print("Chunk read is:", chunk)
                print("Chunk crypted is:", chunk_crypted)
                conn_client.send(chunk_crypted)
                counter += 1
                chunk = padding(chunk)
                counter_q += 1
        else: break
