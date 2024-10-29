from scapy.all import *
from collections import defaultdict

#================================= BruteForce hidden ESSID DETECTION =================================

def brute_hidden_ESSID_detect(packets):
    # List to store probe packet tuples in the form of (timestamp, src_mac, ssid)
    PROBE_Packets_List = []

    # Extract the time of the first packet to use as a reference point
    first_packet_time = float(packets[0].time) if packets else 0  # Avoids errors if packets list is empty

    for pkt in packets:
        if pkt.haslayer("Dot11"):
            if pkt.type == 0 and pkt.subtype == 4:  # Management frame (type 0) and Probe Request (subtype 4)            
                # Get source MAC address (the device sending the request)
                src_mac = pkt.addr2

                # Check for SSID in the Probe Request
                # dot11elt.ID == 0 represents the SSID field
                ssid = pkt["Dot11Elt"].info.decode('utf-8', errors='ignore') if pkt.haslayer("Dot11Elt") and pkt["Dot11Elt"].ID == 0 else "<Hidden SSID>"
            
                # Get packet timestamp as relative seconds from the first packet
                timestamp = float(pkt.time) - first_packet_time

                PROBE_Packets_List.append((timestamp, src_mac, ssid))


    # Check for 50 or more packets within any 3-second window
    threshold_count = 50
    window_duration = 3.0  # seconds

    # Iterate through each packet to check for the threshold condition
    for i in range(len(PROBE_Packets_List)):
        current_time = PROBE_Packets_List[i][0]
    
        # Initialize a counter for packets within the window and a set for SSIDs and MAC addresses
        count_in_window = 0
        ssids_in_window = set()  # To store unique SSIDs
        macs_in_window = set()  # To store unique MAC addresses

        # Count packets within the time window
        for ts, mac, ssid in PROBE_Packets_List:
            if current_time <= ts < current_time + window_duration:
                count_in_window += 1
                ssids_in_window.add(ssid)
                macs_in_window.add(mac)

        # Check if the number of packets exceeds the threshold
        if count_in_window >= threshold_count:
            print(f"Brute-force hidden ESSID attack detected from MAC Addresses:\n{macs_in_window}\nto SSIDs:\n{ssids_in_window}\nwith {count_in_window} packets in the time window of {current_time:.2f} to {current_time + window_duration:.2f} seconds.")
            print("==============================================================================================")
            print("==============================================================================================")

#================================= BruteForce hidden ESSID DETECTION =================================
#================================= ARP replay attack DETECTION =================================

mac_timestamps = defaultdict(list)  # Dictionary to store timestamps for each source MAC address
threshold = 1000  # Threshold for number of packets
time_window = 3  # Time window in seconds
period = None

# Function to check if there are 1000 packets within a 3-second window
def check_replay_attack(timestamps):
    global period
    for i in range(len(timestamps)):
        # Compare the "i" packet timestamp with the timestamp 1000 packets after
        if i + threshold <= len(timestamps):
            time_diff = timestamps[i + threshold - 1] - timestamps[i]
            if time_diff <= time_window:
                period = time_diff
                return True
    return False

def ARP_Replay_Detection(packets):
    # Use as reference packet (first packet)
    first_packet_time = packets[0].time

    # Loop through PCAP to find ARP packets
    for pkt in packets:
        if ARP in pkt:
            # Convert the timestamp to seconds since the first packet captured
            relative_time = pkt.time - first_packet_time
            # Add the time to the relative mac address
            mac_timestamps[pkt.src].append(relative_time)

    # Check for replay attacks for each MAC address
    spoofed_macs = []
    for mac, timestamps in mac_timestamps.items():
        # Sort the timestamps for each MAC address
        timestamps.sort()
        if len(timestamps) >= threshold and check_replay_attack(timestamps):
            spoofed_macs.append(mac)

    # Output the detected spoofed MAC addresses
    if spoofed_macs:
        print(f"Detected ARP replay attack! Spoofed source MAC addresses has 1000 packets within {period} seconds")
        for mac in spoofed_macs:
            print("Spoofed MAC:", mac)
    else:
        print("No ARP replay attacks detected.")

#================================= ARP replay attack DETECTION =================================
#================================= Rogue AP DETECTION =================================
def Rogue_AP_Detection(packets):
    # Dictionary to track SSID and BSSID associations
    ap_info = {}
    # Dictionary to count deauthentication frames from each BSSID
    deauth_count = {}
    # Set to track SSIDs already flagged as potential rogue APs
    flagged_ssids = set()
    for pkt in packets:
        # Check if the packet is a Dot11 (Wi-Fi) packet
        if pkt.haslayer(Dot11):
            # Check if the packet is a beacon or probe response frame (type 0, subtype 8 or 5)
            if pkt.type == 0 and pkt.subtype in (8, 5):
                # Extract SSID and BSSID
                ssid = pkt.info.decode('utf-8', 'ignore')
                bssid = pkt.addr2

                # Check for duplicate SSIDs with different BSSIDs (potential rogue AP)
                if ssid in ap_info:
                    if ap_info[ssid] != bssid and ssid not in flagged_ssids:
                        print(f"Potential Rogue AP Detected: SSID {ssid} has multiple BSSIDs: {ap_info[ssid]} and {bssid}")
                        flagged_ssids.add(ssid)  # Mark this SSID as flagged to avoid repeated messages
                else:
                    # Save the SSID and BSSID if not already in ap_info
                    ap_info[ssid] = bssid

            # Check if the packet is a deauthentication frame (type 0, subtype 12)
            if pkt.type == 0 and pkt.subtype == 12:
                bssid = pkt.addr2
                if bssid:
                    # Increment the count of deauth frames for the BSSID
                    if bssid in deauth_count:
                        deauth_count[bssid] += 1
                    else:
                        deauth_count[bssid] = 1

                    # Check if 10 or more deauth frames are sent
                    if deauth_count.get(ap_info.get(ssid, ''), 0) >= 10:
                        print(f"Rogue AP Confirmed: BSSID {bssid} is the rogue AP due to excessive deauthentication frames.")
                        break  # Stop the loop once a rogue AP is confirmed
                    elif deauth_count.get(bssid, 0) >= 10:
                        print(f"Rogue AP Confirmed: BSSID {ap_info.get(ssid, '')} is the rogue AP due to excessive deauthentication frames.")
                        break  # Stop the loop once a rogue AP is confirmed
    print("Analysis complete.")
#================================= Rogue AP DETECTION =================================
#================================= DEAUTHENTICATION ATTACK AND PASSWORD CRACKING DETECTION =================================
def deauth_password_crack_detect(packets):
    # A counter for deauthentication packets
    cont_deauth_count = 0
    cont_eapol_count = 0
    prev_deauth_count = 0
    password_crack_attempt = 1
    deauth_attempt = 1

    # attacker and victim mac address variables
    bssid = ""
    attacker_mac = ""

    # Loop through all packets and look for deauth and EAPOL packets
    for pkt in packets:
        # Check if the packet is a Dot11 (Wi-Fi) packet
        if pkt.haslayer(Dot11):
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
                        print("Deauthentication attack attempt #" + str(deauth_attempt) + " detected, " + str(cont_deauth_count) + " continuous deauth packets are found")
                        print("Attacker mac address: " + attacker_mac)
                        print("Victim BSSID mac address: " + bssid + "\n")
                        deauth_attempt += 1
            
                    if pkt.haslayer("EAPOL"):
                        cont_eapol_count += 1
                        if cont_deauth_count != 0:
                            prev_deauth_count = cont_deauth_count
                        if cont_eapol_count == 4:
                            print("Possible password cracking attempt #" + str(password_crack_attempt) + " detected")
                            print(str(prev_deauth_count) + " continuous deauth packets detected before client attempted to connect to the wireless point access point")
                            print("================================================================================================================")
                            password_crack_attempt += 1
                    cont_deauth_count = 0
            else:
                cont_eapol_count = 0
    
    if cont_deauth_count > 5:
        print("================================================================================================================")
        print("Deauthentication attack attempt #" + str(deauth_attempt) + " detected, " + str(cont_deauth_count) + " continuous deauth packets are found")
        print("Attacker mac address: " + attacker_mac)
        print("Victim BSSID mac address: " + bssid)
#================================= DEAUTHENTICATION ATTACK AND PASSWORD CRACKING DETECTION =================================

def main():
    # Check if filename argument is provided
    if len(sys.argv) < 2:
        print("Usage: python WI-Guard.py <filename>")
        return

    # Get filename from command-line arguments
    filename = sys.argv[1]

    print("[Select an option:]")
    print("==========================")
    print("Deauth attack & password cracking detection - 1")
    print("Rogue AP detection - 2")
    print("ARP Replay attack detection - 3")
    print("BruteForce hidden ESSID detection - 4")
    
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return

    # Wait for user input and store it in a variable
    selected_option = input("Input option here: ")
    print("\n")

    if(int(selected_option) == 1):
        deauth_password_crack_detect(packets)
    elif(int(selected_option) == 2):
        Rogue_AP_Detection(packets)
    elif(int(selected_option) == 3):
        ARP_Replay_Detection(packets)
    elif(int(selected_option) == 4):
        brute_hidden_ESSID_detect(packets)
    
if __name__ == "__main__":
    main()