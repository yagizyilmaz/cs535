import socket
import os
from threading import Thread, Lock
from Crypto.Protocol.SecretSharing import Shamir
from binascii import unhexlify
import pyDH
import time
import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

lock = Lock()
DH_KEYS = {}
dh = None
dh_pubkey = None
IP_FILE_LIST = {}
MESSAGE_LIST = {}

COMBINER_RUNNING = False
RECEIVE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Received")
if not os.path.exists(RECEIVE_PATH):
    os.mkdir(RECEIVE_PATH)



def decrypt_message(msg_in_bytes, key):
    try:
        key = key[:16]
        if isinstance(key, str):
            key = key.encode()
        b64 = json.loads(msg_in_bytes.decode())
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}
        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        # print("The message was: " + plaintext)
        return plaintext, jv['header']
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


class Regular_Listener(Thread):
    def __init__(self, ip, port):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.s = self.create_socket(self.ip, self.port)
        self.s.listen(5) #What is 5 in here
        print(f"Listening on port: {self.port}")


    @classmethod
    def create_socket(cls, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # disable Nagle algorithm
        s.bind((ip, port))
        return s


    def send_msg(cls, ip, port, msg, msg_type):
        comm = Communication(ip, port)
        s = comm.create_socket()
        print("[!] Sending message with type: ", msg_type)
        info = bytearray() # filename and filesize
        msg_size = len(msg)
        info.extend(bytearray(msg_type.to_bytes(4, 'big')))
        info.extend(bytearray(msg_size.to_bytes(4, 'big')))
        info.extend(bytearray(msg))
        s.send(info)
        s.close()
        del comm


    def handle(self):
        global DH_KEYS
        while True:
            client_socket, address = self.s.accept()
            packet_info = bytearray(client_socket.recv(8))
            if len(packet_info) == 8:
                msg_type = int.from_bytes(packet_info[:4], 'big')
                size = int.from_bytes(packet_info[4:8], 'big')
                print(f"[+] Message Type: {msg_type}\tSize: {size}")
                bytes_read = bytearray(client_socket.recv(size))


                if msg_type == 1:
                    # Diffie Hellman
                    if str(address[0]) not in DH_KEYS.keys():
                        DH_KEYS[str(address[0])] = {}   
                    DH_KEYS[str(address[0])]['PUBKEY'] = int.from_bytes(bytes_read, 'big')
                    dh_sharedkey = dh.gen_shared_key(DH_KEYS[str(address[0])]['PUBKEY'])
                    DH_KEYS[str(address[0])]['SHARED_KEY'] = dh_sharedkey
                    self.send_msg(address[0], 81, dh_pubkey.to_bytes(256, 'big'), 1)
                
                elif msg_type == 2:
                    # Sending fileinfo
                    shared_key = DH_KEYS[str(address[0])]["SHARED_KEY"]
                    dec_msg_bytes, header = decrypt_message(bytes_read, shared_key)
                    dec_msg = dec_msg_bytes.decode()
                    dec_msg_json = json.loads(dec_msg)
                    filename = dec_msg_json['filename']
                    filesize = dec_msg_json['filesize']
                    shamir_on = dec_msg_json['shamir_on']

                    if address[0] not in IP_FILE_LIST.keys():
                        IP_FILE_LIST[address[0]] = {}
                        IP_FILE_LIST[address[0]]['filecount'] = 1
                        IP_FILE_LIST[address[0]]['files'] = {}
                    else:
                        IP_FILE_LIST[address[0]]['filecount'] += 1
                    
                    filecount = IP_FILE_LIST[address[0]]['filecount']
                    IP_FILE_LIST[address[0]]['files'][filecount] = {}
                    IP_FILE_LIST[address[0]]['files'][filecount]["filename"] = filename
                    IP_FILE_LIST[address[0]]['files'][filecount]["filesize"] = filesize
                    IP_FILE_LIST[address[0]]['files'][filecount]["shamir_on"] = shamir_on
                    IP_FILE_LIST[address[0]]['files'][filecount]['combined'] = False
                    IP_FILE_LIST[address[0]]['files'][filecount]['combiner_started'] = False
                    IP_FILE_LIST[address[0]]['files'][filecount]['combine_status'] = f"0/{filesize//16}"
                    self.send_msg(address[0], 81, str(filecount).encode(), 2)
                    print(IP_FILE_LIST)
            client_socket.close()

    def run(self):
        self.handle()
        self.s.close()


class TCP_Listener(Thread):
    def __init__(self, ip, port):
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


    def handle(self):
        global COMBINER_RUNNING
        filesent = False
        client_socket, address = self.s.accept()
        while True:
            packet_info = bytearray(client_socket.recv(12))
            if len(packet_info) == 12:
                filesent = True
                counter = int.from_bytes(packet_info[:4], 'big')
                idx = int.from_bytes(packet_info[4:8], 'big')
                filecounter = int.from_bytes(packet_info[8:12], 'big')
                # print(counter, idx, filecounter)

                # print(f"[+] Counter: {counter}\tidx: {idx}")
                size = 16
                bytes_read = bytearray(client_socket.recv(size))
                # print("Bytes Read", bytes_read)
                # if not bytes_read:
                #     break
                # point = starting_byte
                ip_addr = str(address[0])

                if ip_addr not in MESSAGE_LIST.keys():
                    MESSAGE_LIST[ip_addr] = {}
                if filecounter not in MESSAGE_LIST[ip_addr].keys():
                    MESSAGE_LIST[ip_addr][filecounter] = {}
                    IP_FILE_LIST[ip_addr]["files"][filecounter]["transfer_start"] = time.time()

                if counter not in MESSAGE_LIST[ip_addr][filecounter].keys():
                    MESSAGE_LIST[ip_addr][filecounter][counter] = {}
                ### TIMING ###
                time_diff = ("%.4gs" % (time.time() - float(IP_FILE_LIST[ip_addr]["files"][filecounter]["transfer_start"])))
                IP_FILE_LIST[ip_addr]["files"][filecounter]["transfer_time"] = time_diff
                ### TIMING ###
                if idx != 10:
                    if 'msgs' not in MESSAGE_LIST[ip_addr][filecounter][counter].keys():
                        MESSAGE_LIST[ip_addr][filecounter][counter]["msgs"] = [(idx, bytes_read)]
                    else:
                        MESSAGE_LIST[ip_addr][filecounter][counter]["msgs"].append((idx, bytes_read))
                else:
                    MESSAGE_LIST[ip_addr][filecounter][counter]["combined"] = bytes_read
            else:
                # print(filesent, not COMBINER_RUNNING)
                # print(filesent and not COMBINER_RUNNING)

                if filesent and not COMBINER_RUNNING:
                    filesent = False
                    COMBINER_RUNNING = True
                    print(f"[!] Starting Combiner from Listener of {self.port}")
                    combiner = Combiner()
                    combiner.start()

                client_socket.close()
                client_socket, address = self.s.accept()

        print(f"LISTENER FOR PORT {self.port} STOPPED")


    def run(self):
        self.handle()
        self.s.close()




class Receiver:
    def __init__(self):
        global dh, dh_pubkey
        dh = pyDH.DiffieHellman()
        dh_pubkey = dh.gen_public_key()
        rl0 = Regular_Listener("0.0.0.0", 444)
        rl0.start()
        self.PORTLIST = [25,21,80]

        listeners = [TCP_Listener("0.0.0.0", port) for port in self.PORTLIST]
        for listener in listeners:
            listener.start()



class Combiner(Thread):
    def handle(self):
        global MESSAGE_LIST, COMBINER_RUNNING, IP_FILE_LIST
        print("Combiner Running...")
        # begin = time.time()
        for ip_addr in list(MESSAGE_LIST):
            for filecounter in list(MESSAGE_LIST[ip_addr]):
                total_count = IP_FILE_LIST[ip_addr]['files'][filecounter]['filesize'] // 16 + 1

                ### TIMING ###
                combine_start_timestamp = time.time()
                IP_FILE_LIST[ip_addr]['files'][filecounter]['combine_start'] = combine_start_timestamp
                IP_FILE_LIST[ip_addr]['files'][filecounter]['combiner_started'] = True
                ### TIMING ###

                for counter in list(MESSAGE_LIST[ip_addr][filecounter]):
                    if counter != 'combined_count':
                        if 'combined' not in MESSAGE_LIST[ip_addr][filecounter][counter].keys() and len(MESSAGE_LIST[ip_addr][filecounter][counter]["msgs"]) >= 2:
                            shares = MESSAGE_LIST[ip_addr][filecounter][counter]["msgs"]
                            combined = Shamir.combine(shares)
                            if counter + 1 == total_count:
                                combined = combined[:IP_FILE_LIST[ip_addr]['files'][filecounter]['filesize'] % 16]

                            MESSAGE_LIST[ip_addr][filecounter][counter]['combined'] = combined
                            if 'combined_count' not in MESSAGE_LIST[ip_addr][filecounter].keys():
                                MESSAGE_LIST[ip_addr][filecounter]['combined_count'] = 1
                            else:
                                MESSAGE_LIST[ip_addr][filecounter]['combined_count'] += 1
                            IP_FILE_LIST[ip_addr]['files'][filecounter]['combine_status'] = f"{MESSAGE_LIST[ip_addr][filecounter]['combined_count']}/{total_count - 1}"


                ### TIMING ###
                combine_end_timestamp = time.time()
                IP_FILE_LIST[ip_addr]['files'][filecounter]['combine_end'] = combine_end_timestamp
                time_diff = ("%.4gs" % (combine_end_timestamp - combine_start_timestamp))
                IP_FILE_LIST[ip_addr]['files'][filecounter]['combine_timespent'] = time_diff
                ### TIMING ###


        # print("MESSAGE LIST: ", MESSAGE_LIST)
        for ip_addr in list(MESSAGE_LIST):
            for filecounter in list(MESSAGE_LIST[ip_addr]):
                if IP_FILE_LIST[ip_addr]['files'][filecounter]['filesize'] % 16 != 0:
                    total_count = IP_FILE_LIST[ip_addr]['files'][filecounter]['filesize'] // 16 + 1
                else:
                    total_count = IP_FILE_LIST[ip_addr]['files'][filecounter]['filesize'] // 16
                if 'combined_count' in MESSAGE_LIST[ip_addr][filecounter].keys():
                    # print(MESSAGE_LIST)
                    # print("_________________________\n\n")
                    # print(IP_FILE_LIST)
                    # print(MESSAGE_LIST[ip_addr][filecounter]['combined_count'], total_count)
                    # print(MESSAGE_LIST)
                    # print("CHECK\n\n")
                    # print(MESSAGE_LIST[ip_addr][filecounter]['combined_count'], total_count)
                    # print("\n")
                    if MESSAGE_LIST[ip_addr][filecounter]['combined_count'] == total_count:
                        total_bytes = bytearray()
                        for i in range(total_count):
                            total_bytes.extend(MESSAGE_LIST[ip_addr][filecounter][i]['combined'])
                            

                        IP_FILE_LIST[ip_addr]['files'][filecounter]['combined'] = True
                        # print(total_bytes)
                        plaintext, header = decrypt_message(total_bytes, DH_KEYS[ip_addr]['SHARED_KEY'])
                        
                        print(f"[+] Writing to file...")
                        with open(os.path.join(RECEIVE_PATH, IP_FILE_LIST[ip_addr]['files'][filecounter]['filename']), "wb") as f:
                            f.write(plaintext)

                        del(MESSAGE_LIST[ip_addr][filecounter])
                        # print("MESSAGE LIST AFTER DELETION: ", MESSAGE_LIST)

                ### TIMING ###
                dec_end_timestamp = time.time()
                IP_FILE_LIST[ip_addr]['files'][filecounter]['decrypt_end'] = dec_end_timestamp
                time_diff = ("%.4gs" % (dec_end_timestamp - IP_FILE_LIST[ip_addr]['files'][filecounter]['combine_start']))
                IP_FILE_LIST[ip_addr]['files'][filecounter]['decrypt_timespent'] = time_diff
                ### TIMING ###


        # end = time.time()
        with lock:
            COMBINER_RUNNING = False


    def run(self):
        time.sleep(4)
        self.handle()     



def main():
    receiver = Receiver()



if __name__ == "__main__":
    main()