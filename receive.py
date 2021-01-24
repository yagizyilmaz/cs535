import socket
import os
from threading import Thread
from Crypto.Protocol.SecretSharing import Shamir
from binascii import unhexlify

# shares = []
# for x in range(2):
#     in_str = raw_input("Enter index and share separated by comma: ")
#     idx, share = [ strip(s) for s in in_str.split(",") ]
#     shares.append((idx, unhexlify(share)))
# key = Shamir.combine(shares)



RECIEVE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Received")
if not os.path.exists(RECIEVE_PATH):
    os.mkdir(RECIEVE_PATH)

class Message:
    def __init__(self):
        self.filename, self.filesize = TCP_Listener.get_msg_info()
        self.filename = os.path.join(RECIEVE_PATH, self.filename)
        self.msg_as_bytes = bytearray(self.filesize)
        self.checkpoint = 0
        self.packets = dict()
        self.total_count = self.filesize // 16 + 1

    def combine_all(self):
        print(f"[+] Combining the Messages...")
        total = bytearray()
        for counter in range(1, self.total_count+1):
            if counter % 100 == 0:
                print(f"Combining. Counter: {counter}")
            shares = self.packets[counter]
            # for p in self.packets:
            #     if p["counter"] == counter:
            #         shares.append((p["idx"], p["bytes_read"]))

            combined = Shamir.combine(shares)
            if counter == self.total_count:
                combined = combined[:self.filesize % 16]
            total.extend(combined)
        self.msg_as_bytes = total
        self.write_to_file()


    def write_to_file(self):
        print(f"[+] Writing to file...")
        out = open(self.filename, "wb")
        out.write(self.msg_as_bytes)

class TCP_Listener(Thread):
    #default values
    ip = "0.0.0.0"
    port = 80
    buffer_size = 1024 # we might remove this and use something smaller in get_msg_info

    def __init__(self, ip, port, msg):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.s = self.create_socket(self.ip, self.port)
        self.s.listen(5) # increase?
        print(f"Listening on port: {self.port}")

    @classmethod
    def create_socket(cls, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle algorithm
        s.bind((ip, port))
        return s

    @classmethod
    def get_msg_info(cls): # this one gets file name and size to create a bytearray to construct the file
        s = cls.create_socket(cls.ip, cls.port)
        s.listen(5)
        client_socket, address = s.accept()

        received = client_socket.recv(cls.buffer_size)
        filename, filesize = received[:-8].decode(), int.from_bytes(received[-8:],'big') #first 8 byte is for file name, rest is for size
        #file_bytearray = bytearray(int(filesize))
        filename = os.path.basename(filename)

        client_socket.close()
        s.close()

        return(filename, filesize)

    def handle(self):
        client_socket, address = self.s.accept()
        """while True: # relies on seq_number of packets, revised to starting byte
            packet_info = bytearray(client_socket.recv(8))
            seq_number = int.from_bytes(packet_info[:4], 'big')
            size = int.from_bytes(packet_info[4:8], 'big')
            print(f"{seq_number}, {size}")

            bytes_read = bytearray(client_socket.recv(size))
            if not bytes_read:
                break
            point = msg.checkpoint
            for index, byte in enumerate(bytes_read):
                msg.msg_as_bytes[point+index:point+index+1] = byte.to_bytes(1, 'big')
                msg.checkpoint += 1
        msg.write_to_file()"""

        while True:
            packet_info = bytearray(client_socket.recv(8))
            counter = int.from_bytes(packet_info[:4], 'big')
            idx = int.from_bytes(packet_info[4:8], 'big')
            print(f"[+] Counter: {counter}\tidx: {idx}")
            size = 16
            bytes_read = bytearray(client_socket.recv(size))
            if not bytes_read:
                break
            # point = starting_byte
            if counter not in msg.packets.keys():
                msg.packets[counter] = [(idx, bytes_read)]
            else:
                msg.packets[counter].append((idx, bytes_read))
            # .append({"counter":counter, "idx":idx, "bytes_read":bytes_read})
            # for index, byte in enumerate(bytes_read):
            #     msg.msg_as_bytes[point+index:point+index+1] = byte.to_bytes(1, 'big')
        # msg.write_to_file()

        """
            bytes_read = bytearray(client_socket.recv(self.buffer_size))
            #print(f"{int.from_bytes(bytes_read[:4], 'big')}, {int.from_bytes(bytes_read[4:8], 'big')}")
            bytes_read = bytes_read[8:]
            if not bytes_read:
                break
            point = msg.checkpoint
            for index, byte in enumerate(bytes_read):
                msg.msg_as_bytes[point+index:point+index+1] = byte.to_bytes(1, 'big')
                msg.checkpoint += 1
        msg.write_to_file()
        """

        client_socket.close()

    def run(self):
        self.handle()
        self.s.close()

if __name__ == "__main__":
    msg = Message()

    th1 = TCP_Listener("0.0.0.0", 80, msg)
    th2 = TCP_Listener("0.0.0.0", 25, msg)
    th3 = TCP_Listener("0.0.0.0", 20, msg)

    th1.start()
    th2.start()
    th3.start()

    th1.join()
    th2.join()
    th3.join()

    msg.combine_all()