import sys
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, EAPOL

def extract_handshakes(cap_path, output_path):
    print(f"[*] Loading capture file: {cap_path}...")
    try:
        packets = rdpcap(cap_path)
    except Exception as e:
        print(f"[-] Error reading capture file: {e}")
        return

    ssids = {}

    # 1. Map BSSID to ESSID (hex) from Beacon / Probe Response frames
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11Elt):
            try:
                bssid = pkt[Dot11].addr3.lower()
                ssid_bytes = pkt[Dot11Elt].info
                if isinstance(ssid_bytes, bytes):
                    ssids[bssid] = ssid_bytes.hex()
                else:
                    ssids[bssid] = ssid_bytes.encode('utf-8').hex()
            except Exception:
                continue

    anonce_store = {}
    latest_anonce = {}
    hashes = []

    # 2. Process EAPOL frames with state tracking (M1 + M2 pairing)
    for pkt in packets:
        if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
            continue

        try:
            dot11 = pkt[Dot11]
            eapol = pkt[EAPOL]
            raw_eapol = bytes(eapol)  # Retain the complete 4-byte EAPOL header

            if len(raw_eapol) < 99:
                continue

            # Determine traffic direction
            ds = dot11.FCfield & 0x3
            if ds == 0x01:    # To-DS (Client -> AP)
                mac_ap = dot11.addr1.lower()
                mac_client = dot11.addr2.lower()
            elif ds == 0x02:  # From-DS (AP -> Client)
                mac_ap = dot11.addr2.lower()
                mac_client = dot11.addr1.lower()
            else:
                continue

            # Extract Key Information field (bytes 5:7 in complete EAPOL frame)
            key_info = int.from_bytes(raw_eapol[5:7], byteorder='big')
            key_ver = key_info & 0x07
            is_key_ack = bool(key_info & 0x0080)
            is_key_mic = bool(key_info & 0x0100)

            replay_counter = raw_eapol[9:17]
            nonce = raw_eapol[17:49]

            # Message M1: AP -> Client (No MIC, Key ACK set) -> Store ANonce
            if is_key_ack and not is_key_mic:
                if nonce != b'\x00' * 32:
                    anonce_store[(mac_ap, mac_client, replay_counter)] = nonce
                    latest_anonce[(mac_ap, mac_client)] = nonce

            # Message M2: Client -> AP (MIC set, Key ACK not set) -> Construct Hash
            elif is_key_mic and not is_key_ack:
                # Filter out M4 frames (M4 has a zeroed Nonce; M2 contains SNonce)
                if nonce == b'\x00' * 32:
                    continue

                # Retrieve matching ANonce by Replay Counter or latest recorded
                anonce = anonce_store.get((mac_ap, mac_client, replay_counter))
                if not anonce:
                    anonce = latest_anonce.get((mac_ap, mac_client))

                if not anonce or anonce == b'\x00' * 32:
                    continue

                mic = raw_eapol[81:97].hex()
                anonce_hex = anonce.hex()

                # Zero out MIC field in full EAPOL frame (bytes 81:97)
                eapol_zeroed = raw_eapol[:81] + b'\x00' * 16 + raw_eapol[97:]
                eapol_hex = eapol_zeroed.hex()

                essid_hex = ssids.get(mac_ap, "")
                mac_ap_clean = mac_ap.replace(":", "")
                mac_client_clean = mac_client.replace(":", "")

                # Hashcat 22000 Message Pair Flag (0x80 | key_version = 0x82 for WPA2)
                message_pair_flag = 0x80 | key_ver

                # Hashcat 22000 format:
                # WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID_HEX*ANONCE*EAPOL_FRAME*MESSAGE_PAIR
                hc22000_line = (
                    f"WPA*02*{mic}*{mac_ap_clean}*{mac_client_clean}*"
                    f"{essid_hex}*{anonce_hex}*{eapol_hex}*{message_pair_flag:02x}"
                )
                hashes.append(hc22000_line)

        except Exception:
            continue

    if hashes:
        unique_hashes = sorted(list(set(hashes)))
        with open(output_path, "w") as f:
            for h in unique_hashes:
                f.write(h + "\n")
        print(f"[+] Saved {len(unique_hashes)} valid hash(es) to '{output_path}'.")
    else:
        print("[-] No valid WPA handshakes found in capture file.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python parse_cap.py <file.cap> <output.hc22000>")
        sys.exit(1)

    extract_handshakes(sys.argv[1], sys.argv[2])
