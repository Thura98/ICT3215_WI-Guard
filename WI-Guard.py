from scapy.all import *

DeAuth_PassCrack_packets = rdpcap("Packet_Files/DeAuth_PassCrack.cap")

# A counter for deauthentication packets
cont_deauth_count = 0
prev_deauth_count = 0
password_crack_attempt = 1
deauth_attempt = 1

# attacker and victim mac address variables
bssid = ""
attacker_mac = ""


# print(DeAuth_PassCrack_packets[951])
# print(DeAuth_PassCrack_packets[952].show())

# print(DeAuth_PassCrack_packets[67])
# print(DeAuth_PassCrack_packets[67].addr1)
# print(DeAuth_PassCrack_packets[67].show())

# Loop through all packets and look for deauth and EAPOL packets
for pkt in DeAuth_PassCrack_packets:        
    # Check if packet is an EAPOL packet or a deauth packet
    if (pkt.haslayer("EAPOL") or pkt.haslayer("Dot11Deauth")):
        # Check if packet is a deauth packet
        if pkt.haslayer("Dot11Deauth"):
            cont_deauth_count += 1
            bssid = pkt.addr3
            if(pkt.addr1 != pkt.addr3):
                attacker_mac = pkt.addr1
            elif(pkt.addr2 != pkt.addr3):
                attacker_mac = pkt.addr2
        else:
            if cont_deauth_count > 5:
                print("================================================================================================================")
                print("Deauthentication attack attempt " + str(deauth_attempt) + " detected, " + str(cont_deauth_count) + " continuous deauth packets are found")
                print("Attacker mac address: " + attacker_mac)
                print("Victim BSSID mac address: " + bssid + "\n")
                deauth_attempt += 1
            
            if pkt.haslayer("EAPOL"):
                if cont_deauth_count > 5 and cont_deauth_count != prev_deauth_count:
                    print("Possible password cracking attempt " + str(password_crack_attempt) + " detected")
                    print(str(cont_deauth_count) + " continuous deauth packets detected before client attempted to connect to the wireless point access point")
                    print("================================================================================================================")
                    prev_deauth_count = cont_deauth_count
                    password_crack_attempt += 1

            cont_deauth_count = 0


if cont_deauth_count > 5:
    print("================================================================================================================")
    print("Deauthentication attack attempt " + str(deauth_attempt) + " detected, " + str(cont_deauth_count) + " continuous deauth packets are found")
    print("Attacker mac address: " + attacker_mac)
    print("Victim BSSID mac address: " + bssid)

# References
# https://charlesreid1.com/wiki/Scapy/Pcap_Reader 
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html 
# https://cylab.be/blog/245/network-traffic-analysis-with-python-scapy-and-some-machine-learning?accept-cookies=1 
# https://scapy.readthedocs.io/en/latest/api/scapy.packet.html 