#!/usr/bin/env python3

import socket
import secrets
from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 65431
K3 = b'0123456789123456'
iv = b'abcdabcdabcdabcd'

q = 5
cipher = AES.new(K3, AES.MODE_ECB)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    while True:
        s.listen()
        print("I am listening")
        conn, addr = s.accept()
        K1 = secrets.token_bytes(16)
        K2 = secrets.token_bytes(16)
        with conn:
            print("Connected by", addr)
            print("First key is ", K1)
            print("Second key is ", K2)
            request_of_enc = conn.recv(1024).decode()
            while request_of_enc!= "CBC" and request_of_enc!="OFB" and request_of_enc!="exit":
                message = "[server] Unavailable command! Must be CBC or OFB!"
                conn.send(message.encode())
                request_of_enc = conn.recv(1024).decode()
            if request_of_enc == "exit":
                break

            if request_of_enc == "CBC":
                ciphertext = cipher.encrypt(K1)
            elif request_of_enc == "OFB":
                ciphertext = cipher.encrypt(K2)
            conn.send(ciphertext)
            conn.send(iv)
