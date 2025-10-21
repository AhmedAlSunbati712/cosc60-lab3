"""
Ether.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the Ethernet (Layer 2) packet structure. Supports both construction
             from header parameters and parsing from raw bytes. Provides methods to build
             byte sequences and recursively display encapsulated layers.
"""

import struct
from Packet import Packet
from IP import IP


class Ether(Packet):
    def __init__(self, dest_mac=None, src_mac=None, ethr_type=0x0800, payload=b'', raw=None):
        """
        Description: Initializes an Ethernet frame. Can be built from header fields or parsed from raw bytes.

        @param src_mac: Source MAC address, e.g. "aa:bb:cc:dd:ee:ff"
        @param dest_mac: Destination MAC address, e.g. "ff:ff:ff:ff:ff:ff"
        @param ethr_type: EtherType field (default 0x0800 for IPv4)
        @param payload: Encapsulated payload (IP layer)
        @param raw: Optional raw bytes for parsing
        @returns: None
        """
        if raw: 
        #6 bytes each for the dest and srx mac and 2 bytes for ethr_type
        #unpack the dest_mac and src_mac
            self.dest_mac = ':'.join(f'{b:02x}' for b in raw[0:6])
            self.src_mac = ':'.join(f'{b:02x}' for b in raw[6:12])
            self.ethr_type = struct.unpack('!H', raw[12:14])[0]

            payload_data = raw[14:]
            #ipv4
            if self.ethr_type == 0x0800:
                self.payload= IP(raw=payload_data)
            else:
                self.payload = payload_data
        else:
            self.dest_mac= dest_mac
            self.src_mac= src_mac
            self.ethr_type = ethr_type
            self.payload = payload 

    def to_bytes(self):
        """
        Description: Parses Ethernet header fields from raw bytes and
                     creates an appropriate payload layer (e.g., IP).

        @returns: the byte sequence of the the ethernet frame 
    
      """
        
        #convert destination and source MAC adress into 6 bytes
        dest_bytes= bytes(int(x,16) for x in self.dest_mac.split(":"))
        src_bytes =  bytes(int(x,16) for x in self.src_mac.split(":"))
        #pack the ethernet type as 2 bytes
        eth_type_bytes = struct.pack("!H", self.ethr_type)
        #build payload bytes 
        payload_bytes = self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else b''
        #return full ethernet frame
        return dest_bytes + src_bytes + eth_type_bytes + payload_bytes
   