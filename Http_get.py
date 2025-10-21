#Author: Dejanae Green
#Date: 10/20/25
#Purpose: tester file for the http get request

import socket, subprocess, time, random
from IP import IP
from TCP import TCP
from UDP import UDP
from DNS import DNS
from network_utils import sr
from network_utils import send

INTERFACE = "enp0s3"
SRC_IP = "10.0.2.15"
DOMAIN = "vibrantcloud.org"
#pick a random port
SRC_PORT = random.randint(20000, 60000)
#http port
DST_PORT = 80
#DNS port
DNS_PORT = 53

#DNS query to get the domain IP addr
DNS_pkt = DNS(qname=DOMAIN)
UDP_pkt = UDP(src_port=SRC_PORT, dst_port=DNS_PORT, payload=DNS_pkt, src_ip=SRC_IP, dst_ip="1.1.1.1")
IP_pkt = IP(src_IP=SRC_IP, dest_IP= "1.1.1.1", protocol=17, payload=UDP_pkt)
DNS_pkt.show()

print(IP_pkt.build().hex())




reply = sr(IP_pkt, timeout=7)

while reply:
    if hasattr(reply, 'src_IP') and reply.src_IP == "1.1.1.1":
        break
    reply = sr(IP_pkt, timeout=7)
if not reply or not hasattr(reply, 'payload'):
    raise Exception("No DNS reply received")

#get IP from DNS reply which si the last 4 bytes
#first check if reply payload is in bytes already this check is needed so no errors are thrown
UDP_layer = reply.payload.payload
if isinstance(UDP_layer, bytes):
    UDP_obj = UDP(raw_bytes=UDP_layer)
else:
    #already in raw bytes
    UDP_obj = UDP_layer
DNS_obj = UDP_obj.data 
header = DNS_obj[:12]
qname_len = len(DNS_pkt._encode_qname(DOMAIN)) + 4
answer_offset = 12 + qname_len
vibrant_IP_bytes = DNS_obj[answer_offset + 10: answer_offset + 14]
vibrant_IP = ".".join(str(b) for b in vibrant_IP_bytes)
print(f"[+] {DOMAIN} IP: {vibrant_IP}")

#disable firewall
command = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '-m', 'tcp', '--tcp-flags','RST', 'RST', '-j', 'DROP']
result = subprocess.run(command, check=True, capture_output=True, text=True)

#3 way handshake
#syn
seqN = 1000
SYN_pkt = TCP(src_port=SRC_PORT, dst_port=DST_PORT, seq=seqN, flags=0X02, ip_src=SRC_IP, ip_dst=vibrant_IP)
IP_SYN = IP(src_IP=SRC_IP, dest_IP=vibrant_IP, protocol=6, payload=SYN_pkt)
SYN_ACK_reply = sr(IP_SYN, timeout=3)
if not SYN_ACK_reply:
    raise Exception(" No SYN-ACK reply received")
server_TCP = SYN_ACK_reply.payload.payload
server_seq = server_TCP.seq

#ACK
ACK_pkt = TCP(src_port=SRC_PORT, dst_port=DST_PORT, seq=seqN +1, ack_seq=server_seq+1, FLAGS=0X10, ip_src=SRC_IP, ip_dst=vibrant_IP)
IP_ACK = IP(src_IP=SRC_IP, dest_IP=vibrant_IP, protocol=6, payload=ACK_pkt)
sr(IP_ACK)

#http get request
http_request = f"GET /index.html HTTP/1.0\r\nHost: {DOMAIN}\r\n\r\n".encode()
TCP_pkt = TCP(src_port=SRC_PORT, dst_port=DST_PORT, seq= seqN + 1, ack_seq=server_seq+1, flags=0x18, ip_src=SRC_IP, ip_dst=vibrant_IP, data=http_request)
IP_HTTP = IP (src_IP=SRC_IP, dest_IP=vibrant_IP, protocol=6, payload=TCP_pkt)
HTTP_reply = sr(IP_HTTP, timeout=5)

if HTTP_reply:
    TCP_reply = HTTP_reply.payload.payload
    print("[+] HTTP Response:\n")
    print(TCP_reply.data.decode(errors='ignore'))

#enable firewall again

command = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '-m', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
result = subprocess.run(command, check=True, capture_output=True, text=True)
