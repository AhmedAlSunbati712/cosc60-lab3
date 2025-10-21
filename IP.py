"""
IP.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the IPv4 protocol layer (Layer 3).
             Supports building IPv4 headers, checksum calculation,
             and parsing from raw bytes.
"""

import struct
import socket
from Packet import Packet
from ICMP import ICMP
import random


class IP(Packet):
    def __init__(self, src_IP= None, dest_IP= None, payload=None, ttl=128, protocol=1, raw=None):
        """
        Description: Initializes an IPv4 packet. Can construct from provided
                     fields (for sending) or parse from raw bytes (for receiving).

        @param src_IP: Source IPv4 address.
        @param dest_IP: Destination IPv4 address.
        @param ttl: Time to Live.
        @param payload: the data carried by this layer
        @param protocol: Protocol number (e.g., 6 for TCP, 17 for UDP).
        @param raw: If provided, parse these bytes.
        @returns: None
        """
        # ID: Identification field.
        # flags_frag: Flags + Fragment offset field.
        super().__init__(payload)

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
           
            #split version and ihl into seperate
            self.version = version_ihl >> 4
            self.ihl = version_ihl & 0x0F

            #parse payload
            payload_data = raw[20:]
            if self.protocol == 1:
                self.payload=(ICMP(raw=payload_data))
            else:
                self.payload= payload_data
       

        #default values
        else:
            super().__init__(payload)
            self.version = 4
            self.ihl = 5
            self.tos = 0
            self.ID = random.randint(0, 65535)
            self.flags_frag = 0x4000
            self.TTL = ttl
            self.total_len = 0
            self.protocol = protocol
            self.checksum = 0
            self.src_IP = src_IP
            self.dest_IP = dest_IP
    
#used these sources to help me: https://medium.com/@tom_84912/the-quaint-but-critical-internet-checksum-05c09eb0af77
#https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a?permalink_comment_id=3949455
#https://stackoverflow.com/questions/50321292/calculating-ip-checksum-in-c
    def checksum_IP(self, data):
        """
        Description: Computes IPv4 header checksum.

        @param data: IPv4 header with checksum set to 0.
        @returns: 16-bit checksum.
        """
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
        '''
        Description: Byte representation of the IPv4 packet
        @returns: complete byte sequence of the IP packet
        '''

        version_ihl = (self.version << 4) + self.ihl
        # if self.payload:
        #     payload_b = self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else (self.payload if isinstance(self.payload, bytes) else b'')
        # else:
        #     payload_b = b''
        payload_bytes = self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else b''
        self.total_len = 20 + len(payload_bytes)
    
        #pass in 0 as a place holder for the checksum and convert ip string to bytes
        IP_header = struct.pack('!BBHHHBBH4s4s', version_ihl, self.tos, self.total_len, 
                                self.ID, self.flags_frag, self.TTL, self.protocol, 0, socket.inet_aton(self.src_IP), socket.inet_aton(self.dest_IP))
        #calcuate checksum
        self.checksum = self.checksum_IP(IP_header)
        header = struct.pack('!BBHHHBBH4s4s', version_ihl, self.tos, self.total_len, self.ID, self.flags_frag, 
                                self.TTL, self.protocol, self.checksum, socket.inet_aton(self.src_IP), socket.inet_aton(self.dest_IP))
        #add payload to ipheader
    
        return header + payload_bytes

   
