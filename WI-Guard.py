from scapy.all import *

# PcapReader creates a generator
# it does NOT load the complete file in memory
DeAuth_PassCrack_packets = rdpcap("Packet_Files/DeAuth_PassCrack.cap")

print(DeAuth_PassCrack_packets[0].show())



# References
# https://charlesreid1.com/wiki/Scapy/Pcap_Reader 
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html 
# https://cylab.be/blog/245/network-traffic-analysis-with-python-scapy-and-some-machine-learning?accept-cookies=1 