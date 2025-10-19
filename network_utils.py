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
    sock.sendto(packet_bytes, (pkt.dst_ip, 0))
    sock.close()
    print(f"[send] Sent {len(packet_bytes)} bytes to {pkt.dst_ip} at layer 3.")
    
def sendp(pkt, interface):
    """
    Description: Transmit a packet at Layer 2 (Ethernet). Uses a raw socket with AF_PACKET.
                 You must include the full Ethernet frame (Ether + higher layers).

    @param pkt: The stacked packet object starting at Ether layer.
    @param interface: The name of the network interface to send from (e.g., 'eth0', 'ens33').
    @returns: None
    """
    packet_bytes = pkt.build()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))

    sock.send(packet_bytes)
    sock.close()
    print(f"[sendp] Sent {len(packet_bytes)} bytes on {interface} at layer 2.")


def sr(pkt, timeout=2):
    """
    Description: Sends a packet at Layer 3 and receives a reply.
                 Uses a raw socket (AF_INET, SOCK_RAW) for sending
                 and a Layer 2 raw socket (AF_PACKET) for receiving.

    @param pkt: The stacked packet object starting at IP or Ether layer.
    @param timeout: Timeout in seconds to wait for a reply.
    @returns: The received packet object built from reply bytes.
    """
    # If top layer is Ethernet, move to its payload
    if isinstance(pkt, Ether):
        pkt = pkt.payload

    # Build packet bytes for transmission
    packet_bytes = pkt.build()

    # Send at layer 3
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.sendto(packet_bytes, (pkt.dst_ip, 0))
    print(f"[sr] Sent {len(packet_bytes)} bytes to {pkt.dst_ip} (waiting for reply...)")

    # Receive at layer 2 (any interface)
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(timeout)

    try:
        reply_bytes, addr = recv_sock.recvfrom(65535)
        print(f"[sr] Received {len(reply_bytes)} bytes from {addr}")

        # Construct an Ether object from received bytes
        reply_pkt = Ether(reply_bytes)
        reply_pkt.show()
        return reply_pkt

    except socket.timeout:
        print("[sr] Timeout waiting for reply.")
        return None

    finally:
        send_sock.close()
        recv_sock.close()

def sniff(timeout=5):
    """
    Description: Captures one packet at Layer 2 on any interface.
                 Builds a Packet hierarchy (starting from Ether) from received bytes
                 and displays it using the show() method.

    @param timeout: Timeout in seconds to wait for a packet.
    @returns: The captured packet object built from received bytes.
    """
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(timeout)

    try:
        pkt_bytes, addr = recv_sock.recvfrom(65535)
        print(f"[sniff] Captured {len(pkt_bytes)} bytes from {addr}")

        # Parse the packet starting at Ethernet
        pkt = Ether(pkt_bytes)
        pkt.show()
        return pkt

    except socket.timeout:
        print("[sniff] Timeout: no packet captured.")
        return None

    finally:
        recv_sock.close()