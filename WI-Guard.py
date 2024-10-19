from scapy.all import *

DeAuth_PassCrack_packets = rdpcap("Packet_Files/DeAuth_PassCrack.cap")

# Initialize a counter for deauthentication packets
deauth_count = 0

bssid = ""
attacker_mac = ""

print(DeAuth_PassCrack_packets[951])
print(DeAuth_PassCrack_packets[951].show())

# print(DeAuth_PassCrack_packets[67])
# print(DeAuth_PassCrack_packets[67].addr1)
# print(DeAuth_PassCrack_packets[67].show())

# Loop through all packets and look for deauth packets
for pkt in DeAuth_PassCrack_packets:
    if pkt.haslayer("Dot11Deauth"):
        deauth_count += 1
        bssid = pkt.addr3
        if(pkt.addr1 != pkt.addr3):
            attacker_mac = pkt.addr1
        elif(pkt.addr2 != pkt.addr3):
            attacker_mac = pkt.addr2

if deauth_count > 5:
    print("Deauthentication attack detected")
    print("Attacker mac address: " + attacker_mac)
    print("Victim BSSID mac address: " + bssid)
else:
    print("Deauthentication attack NOT detected")

# References
# https://charlesreid1.com/wiki/Scapy/Pcap_Reader 
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html 
# https://cylab.be/blog/245/network-traffic-analysis-with-python-scapy-and-some-machine-learning?accept-cookies=1 
# https://scapy.readthedocs.io/en/latest/api/scapy.packet.html 