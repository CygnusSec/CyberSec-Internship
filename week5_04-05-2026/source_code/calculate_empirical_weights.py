import os
from collections import Counter
from scapy.all import PcapReader, DNSQR

# ==========================================
# 1. CONFIGURATION & FILE PATHS
# ==========================================
MALWARE_PCAPS = [
    "Attacks/light_audio.pcap",
    "Attacks/light_compressed.pcap",
    "Attacks/light_exe.pcap",
    "Attacks/light_image.pcap",
    "Attacks/light_text.pcap",
    "Attacks/light_video.pcap"
]

BENIGN_PCAP = "Benign/benign.pcap"
BENIGN_TXT = "Benign/domains.txt"

# Mapping QTYPE integers to readable names
QTYPE_MAP = {1: "A", 5: "CNAME", 16: "TXT", 28: "AAAA", 255: "ANY"}

# ==========================================
# 2. DATA EXTRACTION LOGIC
# ==========================================
def count_qtypes_in_pcap(filepath):
    """Reads a PCAP file iteratively to save RAM and counts DNS QTYPEs."""
    qtype_counter = Counter()
    if not os.path.exists(filepath):
        print(f"[!] Warning: File not found - {filepath}")
        return qtype_counter

    print(f"[*] Parsing PCAP: {filepath}...")
    try:
        # Using PcapReader instead of rdpcap to prevent memory exhaustion
        with PcapReader(filepath) as pcap_reader:
            for packet in pcap_reader:
                if packet.haslayer(DNSQR):
                    qtype = packet[DNSQR].qtype
                    qtype_counter[qtype] += 1
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        
    return qtype_counter

def count_qtypes_in_txt(filepath):
    """Reads a text file of domains. Assumes standard 'A' record (Type 1) queries."""
    qtype_counter = Counter()
    if not os.path.exists(filepath):
        print(f"[!] Warning: File not found - {filepath}")
        return qtype_counter

    print(f"[*] Parsing TXT : {filepath}...")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Assign QTYPE 1 (A record) to all entries in domains.txt
            qtype_counter[1] += len(lines)
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        
    return qtype_counter

# ==========================================
# 3. MAIN EXECUTION & STATISTICAL ANALYSIS
# ==========================================
def main():
    print("[*] ===============================================")
    print("[*] DNS RECORD TYPE EMPIRICAL WEIGHT CALCULATOR")
    print("[*] ===============================================\n")

    malware_counts = Counter()
    benign_counts = Counter()

    # Process Malware Data
    print("[*] --- Processing Malware Dataset ---")
    for pcap in MALWARE_PCAPS:
        malware_counts.update(count_qtypes_in_pcap(pcap))

    # Process Benign Data (PCAP + TXT)
    print("\n[*] --- Processing Benign Dataset ---")
    benign_counts.update(count_qtypes_in_pcap(BENIGN_PCAP))
    benign_counts.update(count_qtypes_in_txt(BENIGN_TXT))

    # Calculate Totals
    total_malware = sum(malware_counts.values())
    total_benign = sum(benign_counts.values())

    if total_malware == 0 or total_benign == 0:
        print("\n[!] Error: Insufficient data extracted. Please check file paths.")
        return

    print("\n[*] ===============================================")
    print("[*] EMPIRICAL WEIGHT RESULTS (INFORMATION GAIN)")
    print("[*] ===============================================")
    
    # Collect all unique QTYPEs found across both datasets
    all_qtypes = set(malware_counts.keys()).union(set(benign_counts.keys()))

    print(f"{'QTYPE':<10} | {'NAME':<6} | {'MALWARE %':<12} | {'BENIGN %':<12} | {'WEIGHT (Malware/Benign)':<25}")
    print("-" * 75)

    for qtype in sorted(all_qtypes):
        name = QTYPE_MAP.get(qtype, f"UNK({qtype})")
        
        # Calculate percentages
        mal_pct = (malware_counts[qtype] / total_malware) * 100
        ben_pct = (benign_counts[qtype] / total_benign) * 100

        # Calculate Weight Ratio (Add small epsilon 0.001 to prevent division by zero)
        epsilon = 0.001
        weight = mal_pct / (ben_pct + epsilon)

        # Print formatted row
        print(f"{qtype:<10} | {name:<6} | {mal_pct:>8.2f} % | {ben_pct:>8.2f} % | {weight:>10.2f}")

    print("\n[*] Analysis Complete.")
    print("[*] Instruction: Use the final 'WEIGHT' column values to update 'get_qtype_weight(qtype)' function.")

if __name__ == "__main__":
    main()