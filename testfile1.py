#Nmae: Dejanae Green
#Date: 10/19/25
#Purpose: tester file for the ICMP ping lab3
from Ether import Ether
from IP import IP
from ICMP import ICMP
import time
from network_utils import send
from network_utils import sendp
from network_utils import sniff
from network_utils import sr

# =========================
# ICMP Test Function
# =========================
if __name__ == "__main__":
    INTERFACE = "enp0s3"
    MY_IP = "10.0.2.15"
    MY_MAC = "08:00:27:e2:a4:11"
    DST_MAC = "52:55:0a:00:02:02"
    DST_IP = "173.201.179.249"  # vibrantcloud.org IP

    print("=== ICMP Echo Test ===")
    
    # Build ICMP Echo Request packet
    pkt = Ether(src_mac=MY_MAC, dest_mac=DST_MAC) / \
          IP(src_IP=MY_IP, dest_IP=DST_IP) / \
          ICMP(icmp_type=8, code=0, ID=1, seq=1)

    # Show packet structure
    pkt.show()

    # Send at Layer 3
    send(pkt)
    time.sleep(1)

    # Send at Layer 2
    sendp(pkt, INTERFACE)
    time.sleep(1)

    # Sniff one packet
    #sniff here because if sniffed at end wont work
    print(f"[*] Sniffing for one packet at Layer 2...")
    sniffed_pkt = sniff(timeout=5)
    if sniffed_pkt:
        print("[+] Sniffed packet sucessfully!")
    else:
        print("[-] No packet sniffed.")

    # Send + receive (Layer 3 + reply)
    reply = sr(pkt, timeout=5)
    if reply:
        print("[+] ICMP reply received!")

   
    pkt_bytes = pkt.build()
    print(f"[*] Final packet length: {len(pkt_bytes)} bytes")


