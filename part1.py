#Nmae: Dejanae Green
#Date: 10/15/25
#Purpose Ether, ICMP, IP classes for network layers (Lab 3 CS 60)
import socket, struct
import time
class Packet:
    def __init__(self, payload=None):
        """
        Description: Initializes a Packet instance. Each packet can contain another packet
                     as its payload, forming a recursive structure (Ether -> IP -> TCP -> DNS).

        @param payload: (Packet or None) The next protocol layer encapsulated by this one.
        @returns: None
        """
        self.payload = payload
    def build(self):
        """
        Description: Recursively constructs the byte representation of this packet and all encapsulated layers.
                     Each subclass should override this method to include its own header fields in 'header_bytes'.
                     The payload’s build() method is then called to append its bytes.

        @returns: (bytes) The full byte sequence of the current layer and all nested payloads.
        """
        packet_bytes = self.to_bytes() if hasattr(self, 'to_bytes') else b''
        if self.payload: 
            packet_bytes += self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else (self.payload if isinstance(self.payload, bytes) else b'')# Build the bytes of the payload layer recursively
        return packet_bytes
    def show(self, indent=0):
        """
        Description: Prints a hierarchical, human-readable view of the packet’s header fields and payload layers.
                     Each level of indentation represents a deeper encapsulation.

        @param indent: (int) The indentation level used for nested printing.
        @returns: None
        """
        print(" " * indent + f"### {self.__class__.__name__} ###")
        for key, value in vars(self).items():
            if key != "payload":
                print(" " * (indent + 1) + f"{key}: {value}")
        if self.payload:
            self.payload.show(indent + 1)

    def __truediv__(self, other):
        """
        Description: overides the / operator to stack apcket layers
        @param other: (packet) the next layer to encapsualte within this one
        @returns: (packet) Curr packet instance with its payload set to other
        """
        if self.payload is None:
            self.payload = other
        else:
            self.payload / other
        return self
        #if ip layer is followed by TCP or UDP fill in Ip adress for the checksum calcualtions
        # if isinstance(self, IP) and isinstance(other, (TCP, UDP)):
        #     other.src_IP = self.src_IP
        #     other.dest_IP = self.dest_IP
        return self
class Ether(Packet):
    #destination and source mac
    #type of protocol in payload like IP or ARp
    #raw is the bytes being recieved
    #payload is the data that belongs to the next 
    def __init__(self, dest_mac=None, src_mac=None, ethr_type=0x0800, payload=None, raw=None):
        if raw:
            #first 14 bytes of the raw bytes is the ethernet header 
            #6 bytes each for the dest and srx mac and 2 bytes for ethr_type
            self.dest_mac_bytes, self.src_mac_bytes, self.ethr_type = struct.unpack("!6s6sH", raw[:14])
            
            #unpack the dest_mac and src_mac
            self.dest_mac = ':'.join(f'{b:02x}' for b in self.dest_mac_bytes)
            self.src_mac = ':'.join(f'{b:02x}' for b in self.src_mac_bytes)
            super().__init__(payload)
        else:
            self.dest_mac= dest_mac
            self.src_mac= src_mac
            self.ethr_type = ethr_type
            super().__init__(payload)

    
    def to_bytes(self):
       #turn dest amc and src mac into bytes
        dest_bytes = bytes.fromhex(self.dest_mac.replace(':', ''))
        src_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        header = struct.pack('!6s6sH', dest_bytes, src_bytes, self.ethr_type)
        #get payload bytes
        if self.payload:
            payload_b = self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else (self.payload if isinstance(self.payload, bytes) else b'')
        else:
            payload_b = b''
        return header + payload_b

class IP(Packet):
    #total time to live internt header length
    def __init__(self, src_IP= None, dest_IP= None, payload=None, ttl=128, protocol=1, raw=None):
        if raw:
            #first 20 bytes is IP header
            header = raw[:20]
            #1byter for the version+ihl and 1 byte TOS  2 bytes eahc for tal length, if, flags_frag
            #1 byte each for ttl and protocol. 2 bytes for checker sum, and 4 bytes each for src Ip and destip
            labels = struct.unpack('!BBHHHBBH4s4s', header)
            version_ihl = labels[0]
            self.tos = labels[1]
            self.total_len = labels[2]
            self.ID = labels[3]
            self.flags_frag = labels[4]
            self.TTL = labels[5]
            self.protocol = labels[6]
            self.checksum = labels[7]
            self.src_IP = socket.inet_ntoa(labels[8])
            self.dest_IP = socket.inet_ntoa(labels[9])
            super().__init__(payload)

            #split version and ihl into seperate
            self.version = version_ihl >> 4
            self.ihl = version_ihl & 0x0F

        #default values
        else:
            super().__init__(payload)
            self.version = 4
            self.ihl = 5
            self.tos = 0
            self.ID = 0
            self.flags_frag = 0
            self.TTL = 128
            self.total_len = 0
            self.protocol = 1
            self.checksum = 0
            self.src_IP = src_IP
            self.dest_IP = dest_IP
            


#used these sources to help me: https://medium.com/@tom_84912/the-quaint-but-critical-internet-checksum-05c09eb0af77
#https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a?permalink_comment_id=3949455
#https://stackoverflow.com/questions/50321292/calculating-ip-checksum-in-c
    def checksum_IP(self, data):
        #if odd add extra bit
        if len(data) % 2:
            data += b'\x00'
        #interpt data as a 16 bit big-endian word
        sumd = sum(struct.unpack('!%dH' % (len(data) //2), data))
        #carry operations. handles overflow from the 16 bits
        sumd = (sumd >> 16) + (sumd & 0xFFFF)
        sumd += sumd >> 16
        #complment of the 16-bit sum mask to 16 bits
        return (~sumd) & 0xFFFF


        
    def to_bytes(self):
        version_ihl = (self.version << 4) + self.ihl
        if self.payload:
            payload_b = self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else (self.payload if isinstance(self.payload, bytes) else b'')
        else:
            payload_b = b''
        total_len = self.ihl * 4 + len(payload_b)
        #pass in 0 as a place holder for the checksum and convert ip string to bytes
        IP_header = struct.pack('!BBHHHBBH4s4s', version_ihl, self.tos, total_len, 
                                self.ID, self.flags_frag, self.TTL, self.protocol, 0, socket.inet_aton(self.src_IP), socket.inet_aton(self.dest_IP))
        #calcuate checksum
        self.checksum = self.checksum_IP(IP_header)
        IP_header = struct.pack('!BBHHHBBH4s4s', version_ihl, self.tos, total_len, self.ID, self.flags_frag, 
                                self.TTL, self.protocol, self.checksum, socket.inet_aton(self.src_IP), socket.inet_aton(self.dest_IP))
        #add payload to ipheader
    
        return IP_header + payload_b
#type is the tupe of message it is like echo request and code is more specific reason for the error
class ICMP(Packet):
    def __init__(self, icmp_type= 8, code=0, payload=b'', ID=0, seq=0, raw= None):
        if raw:
            header = raw[:8]
            #1 byte for type and code each 2 bytes for chcksum, header and sequence number each
            labels = struct.unpack('!BBHHH', header)
            self.icmp_type = labels[0]
            self.code = labels[1]
            self.checksum = labels[2]
            self.ID = labels[3]
            self.seq = labels[4]
            #make sure payload in bytes
            payload_data = raw[8:] if raw[8:] else b''
            super().__init__(payload_data)
        #default if no packet recieved
        else:
            #ensure payload is bytes
            if payload is None:
                payload = b''
            super().__init__(payload)
            #place holder will calculae in to_bytes
            self.checksum = 0
            self.icmp_type = int(icmp_type)
            self.ID = int(ID)
            self.seq = int(seq)
            self.code = int(code)
            

#cite: https://stackoverflow.com/questions/20247551/icmp-echo-checksum
    def checksum_ICMP(self, data):
        #similiar to the IP check sum calculations
        #if odd number add an extra bit
        if len(data) % 2:
            data += b'\x00'
        sumd = sum(struct.unpack('!%dH' % (len(data)//2), data))
        #carry operations. handles overflow from the 16 bits
        sumd = (sumd >> 16) + (sumd & 0xFFFF)
        sumd += sumd >> 16
        #complment of the 16-bit sum mask to 16 bits
        return (~sumd) & 0xFFFF

    def to_bytes(self):
        if self.payload:
            if hasattr(self.payload, 'build'):
                payload_b = self.payload.build()
            else:
                payload_b = self.payload if isinstance(self.payload, bytes) else b''
        else:
            payload_b = b''
        #placeholder checksum will calcualte later
        #header with zero checksum placeholder
        header_0CS = struct.pack('!BBHHH', self.icmp_type, self.code, 0, self.ID, self.seq)
        # add payload on top of header
        header_CS= header_0CS + payload_b
        #calcualte checksum then add that checksum to the header
        self.checksum = self.checksum_ICMP(header_CS)
        header = struct.pack('!BBHHH', self.icmp_type, self.code, self.checksum, self.ID, self.seq)
        return header + payload_b

pkt = Ether(src_mac="aa:bb:cc:dd:ee:ff", dest_mac="11:22:33:44:55:66") / \
      IP(src_IP="192.168.0.10", dest_IP="8.8.8.8") / \
      ICMP(icmp_type=8, code=0, payload=b'', ID=1, seq=1)
#testing code for first 3
pkt.show()
raw = pkt.build()
print(raw)

def send(packet):
    #if packet starts with ether skip ether and send from IP
    if isinstance(packet, Ether):
        #layer 3 packet
        l3_pkt = packet.payload
    else:
        l3_pkt = l3_pkt
    
    if l3_pkt is None:
        raise ValueError(" NO IP layer found to send")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    #recurssibely build the bytes and send it
    packet_bytes = l3_pkt.build()
    dest_ip = l3_pkt.dest_IP
    sock.sendto(packet_bytes, (dest_ip, 0))
    print(f"[+] sent packet to {dest_ip} (layer 3)")
    #close the socket
    sock.close()

def sendp(packet, interface):
    #packet must start with ether to send
    if not isinstance(packet, Ether):
        raise ValueError("Packet msut start with Ether to send")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    packet_bytes = packet.build()
    sock.send(packet_bytes)
    print(f"[+] sent packet on {interface} (layer 2)")
#close the socket
    sock.close()

def sr(packet, timeout=2):
    if isinstance(packet, Ether):
        l3_pkt= packet.payload
    else:
        l3_pkt = packet
    if l3_pkt is None:
        raise ValueError(" No IP layer found to send")
    
    #send socket
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    dest_ip = l3_pkt.dest_IP
    send_sock.sendto(l3_pkt.build(), (dest_ip, 0))
    print( f"[+] sent packet to {dest_ip}, waiting for reply...")

    #recieve socket
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(timeout)

    try:
        raw_bytes, addr = recv_sock.recvfrom(65535)
        pkt_recv = Ether(raw=raw_bytes)
        print("[+] Received reply")
        pkt_recv.show()
        return pkt_recv 
    #if no reply recieved by timeout send message and return none
    except socket.timeout:
        print("[-] Timeout: No reply received")
        return None
    finally:
        #close both sockets
        send_sock.close()
        recv_sock.close()

def sniff():
    #open socket to recieve packet
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(5)
    try:
        raw_bytes,addr = recv_sock.recvfrom(65535)
        pkt_recv = Ether(raw=raw_bytes)
        print("[+] Sniffed a packet")
        #print what was recieved
        pkt_recv.show()
        return pkt_recv
    except socket.timeout:
        #timeout and no packet was recieved on socket
        print("[-] Timeout: No packet recieved")
        return None
    finally:
        #close sock
        recv_sock.close()





