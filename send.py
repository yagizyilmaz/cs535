import socket
import os
from threading import Thread
import time
import random
from Crypto.Protocol.SecretSharing import Shamir

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


class TCP_Sender:
    dst_ip = "x.x.x.x"
    dst_port = 80
    #buffer_size = 4096
    #buffer_size = 1024
    #content_size = buffer_size - 8

    def __init__(self, filename, filesize, dst_ip):
        #Thread.__init__(self)
        self.filename = filename
        self.filesize = filesize
        self.dst_ip = dst_ip

        """    @classmethod
    def create_socket(cls, ip=dst_ip, port=dst_port):
        print(f"[+] Connecting to {ip}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle algorithm
        s.connect((ip, port))
        print("[+] Connected.")
        return s"""

    @classmethod
    def send_info(cls, filename, filesize, ip=dst_ip, port=dst_port):
        comm = Communication(ip, port)
        s = comm.create_socket()

        info = bytearray() # filename and filesize
        info.extend(filename.encode())
        info.extend(bytearray(filesize.to_bytes(8, 'big')))
        s.send(info)
        s.close()
        del comm


    def send_file(self):
        comm = Communication(self.dst_ip, 80)
        comm2 = Communication(self.dst_ip, 20)
        comm3 = Communication(self.dst_ip, 25)

        s = comm.create_socket()
        s2 = comm2.create_socket()
        s3 = comm3.create_socket()

        s_list = [s, s2, s3]

        with open(self.filename, "rb") as f:
            counter = 0
            left = self.filesize # amount of data left to be sent
            while True:
                counter += 1

                size = 16

                if (left // size):
                    sent = size
                else:
                    sent = left % size


                bytes_read = f.read(size)
                if len(bytes_read) != 0 and len(bytes_read) != 16:
                    bytes_read += b'\x00' * (16 - len(bytes_read))

                if not bytes_read: # break when there's nothing to be sent
                    break

                shares = Shamir.split(2, 3, bytes_read)
                for ctr, (idx, share) in enumerate(shares):
                    packet = bytearray()
                    packet.extend(bytearray((counter).to_bytes(4, 'big')))
                    packet.extend(bytearray((idx).to_bytes(4, 'big')))
                    packet.extend(bytes_read)
                    s_list[ctr].sendall(packet)

                # select_conn = random.randint(0,2)
                # s_list[select_conn].sendall(packet)

                left -= (sent) # update amount of data that will be sent
        s.close() # close the socket


if __name__ == "__main__":
    filename = "arch.jpg"
    filesize = os.path.getsize(filename)

    TCP_Sender.send_info(filename, filesize, "127.0.0.1", 80)
    time.sleep(0.1) # this one is used to make sure that filename, and filesize sent
    sender = TCP_Sender(filename, filesize, "127.0.0.1")
    sender.send_file()
