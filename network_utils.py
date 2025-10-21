import socket
import socket
from Ether import Ether


def send(pkt):
    """
    Description: Transmit a packet at Layer 3 (IP). Uses a raw socket with AF_INET.
                 The socket automatically adds Ethernet headers and FCS.


    @param pkt: The stacked packet object starting at IP or Ether layer.
    @returns: None
    """
    if isinstance(pkt, Ether):
        pkt = pkt.payload # move to layer 3
   
    # Build bytes (Ether is skipped, starts from IP layer)
    packet_bytes = pkt.build()


    # Create new raw socket for layer 3 transmission
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)


    # Send using destination IP from IP layer
    sock.sendto(packet_bytes, (pkt.dest_IP, 0))
    sock.close()
    print(f"[+] sent packet to {pkt.dest_IP} (layer 3)")
    sock.close()
   
def sendp(packet, interface):
    """
    Description: Transmit a packet at Layer 2 (Ethernet). Uses a raw socket with AF_PACKET.
                 You must include the full Ethernet frame (Ether + higher layers).


    @param pkt: The stacked packet object starting at Ether layer.
    @param interface: The name of the network interface to send from (e.g., 'eth0', 'ens33').
    @returns: None
    """
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
    """
    Description: Sends a packet at Layer 3 and receives a reply.
                 Uses a raw socket (AF_INET, SOCK_RAW) for sending
                 and a Layer 2 raw socket (AF_PACKET) for receiving.


    @param pkt: The stacked packet object starting at IP or Ether layer.
    @param timeout: Timeout in seconds to wait for a reply.
    @returns: The received packet object built from reply bytes.
    """
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




def sniff(timeout=5):
    """
    Description: Captures one packet at Layer 2 on any interface.
                 Builds a Packet hierarchy (starting from Ether) from received bytes
                 and displays it using the show() method.




    @returns: The captured packet object built from received bytes.
    """
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
