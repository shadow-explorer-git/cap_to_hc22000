# WPA/WPA2 Handshake Extractor (`hc22000`)

A lightweight Python utility designed to parse 802.11 packet capture files (`.cap` / `.pcap`) and extract WPA/WPA2 4-way handshakes into the **Hashcat mode 22000** format (`WPA*02*...`).

It accurately pairs Authenticator Nonces (ANonce from Message 1) with Supplicant MICs (from Message 2) and formats output to match the specifications of official tools like `hcxpcapngtool`.

---

## Requirements

* **Python**: `3.7+`
* **Scapy**: `scapy==2.7.0`

### Installation

Install `scapy` using `pip`:

```bash
pip install scapy
```

### Usage
```bash
python parse_cap.py <file.cap> <output.hc22000>
```
---

## Capabilities & Features

* **Hashcat Mode 22000 Compliance**: Generates fully compliant Hashcat 22000 hash lines including full EAPOL headers, zeroed MIC fields, and exact byte alignments.
* **Stateful M1 + M2 Handshake Pairing**: Tracks 4-way handshake states across packets. Automatically correlates the AP's `ANonce` (M1) with the Client's `MIC` (M2) using MAC addresses and EAPOL Replay Counters.
* **Message Pair Flag Injection**: Computes and appends the standard Message Pair Flag (`0x80 | key_version`), outputting `82` for verified WPA2-PSK (AES-CCMP) handshake pairs.
* **Smart Frame Filtering**: Automatically ignores invalid/incomplete handshakes and discards Message 4 (M4) frames (which lack valid nonces), preventing dirty or uncrackable hash lines.
* **Automatic ESSID Resolution**: Maps BSSIDs to network names (ESSIDs) by scanning 802.11 Beacon and Probe Response frames in the capture file.
* **Deduplication**: Automatically cleans and deduplicates output hash lines before saving.

