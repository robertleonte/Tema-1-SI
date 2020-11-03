import socket

from Crypto.Cipher import AES

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT_B = 65432
q = 5
K3 = b'0123456789123456'
counter = 1
cipher = AES.new(K3, AES.MODE_ECB)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def depad(chunk):
    counter = 0
    for byte in chunk:
        if byte > 0 and byte < 16:
            if len(chunk[:counter]) == 16 - byte:
                length = byte
                chunk_random = bytes()
                chunk_random += bytes([length]) * length
                if chunk[counter:] == chunk_random:
                    return chunk[:counter]
        counter += 1
    return chunk


def ofb_decrypt(input, chunk_crypted, cipher_to_use):
    crypted = cipher_to_use.encrypt(input)
    plaintext = byte_xor(chunk_crypted, crypted)
    return plaintext, crypted


def cbc_decrypt(input, chunk_crypted, cipher_to_use):
    decrypted = cipher_to_use.decrypt(chunk_crypted)
    plaintext = byte_xor(input, decrypted)
    return plaintext


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_client:
    s_client.connect((HOST, PORT_B))
    end_of_file = False
    while True:
        if not end_of_file:
            request_of_enc = s_client.recv(16).decode()
            if request_of_enc == "exit":
                break
            response_key = s_client.recv(16)
            iv = s_client.recv(16)
            decrypted = cipher.decrypt(response_key)
            print("Cheia este", decrypted)
            cipher_main = AES.new(decrypted, AES.MODE_ECB)
            counter_q = 0
            while counter_q < q:
                chunk_crypted = s_client.recv(16)
                if not chunk_crypted:
                    end_of_file = True
                    break
                if counter == 1:
                    if request_of_enc == "OFB":
                        chunk_decrypted, previous = ofb_decrypt(iv, chunk_crypted, cipher_main)
                    elif request_of_enc == "CBC":
                        chunk_decrypted = cbc_decrypt(iv, chunk_crypted, cipher_main)
                        previous = chunk_crypted
                else:
                    if request_of_enc == "OFB":
                        chunk_decrypted, previous = ofb_decrypt(previous, chunk_crypted, cipher_main)
                    elif request_of_enc == "CBC":
                        chunk_decrypted = cbc_decrypt(previous, chunk_crypted, cipher_main)
                        previous = chunk_crypted

                counter += 1
                counter_q += 1
                print("Chunk received is:", chunk_crypted)
                print("Chunk decrypted is:", depad(chunk_decrypted).decode())
        else:
            break
