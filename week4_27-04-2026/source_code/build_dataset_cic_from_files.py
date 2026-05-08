import os
import re
import math
from collections import Counter
import tldextract
from scapy.all import rdpcap, DNSQR, UDP

# ==========================================
# 1. FEATURE EXTRACTION
# ==========================================
def calculate_entropy(domain_string):
    if not domain_string:
        return 0.0
    entropy = 0
    length = len(domain_string)
    character_counts = Counter(domain_string)
    for count in character_counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

def extract_features(fqdn):
    fqdn = str(fqdn).strip()
    if fqdn.endswith('.'):
        fqdn = fqdn[:-1]
        
    require = tldextract.extract(fqdn)
    subdomain = require.subdomain
    
    # FOCUS ONLY ON SUBDOMAIN (ANTI-OVERFITTING)
    if not subdomain:
        return [0, 0.0, 0.0]

    length = len(subdomain)
    entropy = calculate_entropy(subdomain)
    digit_count = len(re.findall(r'\d', subdomain))
    digit_ratio = round(digit_count / length, 3) if length > 0 else 0.0

    return [length, entropy, digit_ratio]

# ==========================================
# 2. NOISE FILTERING FOR MALWARE SAMPLES
# ==========================================
# Malware samples contains a lot of "background noise"
KNOWN_OS_NOISE = [
    'arpa', 'local', 'ubuntu.com', 'microsoft.com', 
    'windows.com', 'ntp.org', 'google.com', 'bind'
]

def is_background_noise(fqdn):
    fqdn_lower = str(fqdn).lower()
    for noise in KNOWN_OS_NOISE:
        if fqdn_lower.endswith(noise):
            return True
    return False

# ==========================================
# 3. PROCESSING FUNCTIONS
# ==========================================
def process_pcap_file(pcap_path, label, output_file):
    print(f"[*] Processing PCAP: {pcap_path} (Label: {label})...")
    try:
        packets = rdpcap(pcap_path)
        extracted_count = 0
        noise_dropped = 0
        
        with open(output_file, "a", encoding="utf-8") as f:
            for pkt in packets:
                if pkt.haslayer(DNSQR) and pkt.haslayer(UDP):
                    query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                    
                    if not query_name or len(query_name) < 4:
                        continue
                    
                    # Check for data poisoning (MALWARE)
                    if label == 1:
                        # 1. Remove trash background noise (OS-generated queries) before feature extraction
                        if is_background_noise(query_name):
                            noise_dropped += 1
                            continue
                            
                        # 2. Extract feature to check length
                        features = extract_features(query_name)
                        
                        # 3. If length < 20, possibly a noisy background query, drop it to improve model quality
                        if features[0] < 20:
                            noise_dropped += 1
                            continue
                    else:
                        # For benign data, extract features directly without aggressive filtering
                        features = extract_features(query_name)

                    # Write to output file: label,length,entropy,digit_ratio
                    feature_str = ",".join(map(str, features))
                    f.write(f"{label},{feature_str}\n")
                    extracted_count += 1
                    
        print(f"  -> Extracted {extracted_count} clean queries. (Dropped {noise_dropped} noisy background queries)")
    except Exception as e:
        print(f"[!] Error processing {pcap_path}: {e}")

def process_txt(txt_path, label, out_file, max_lines=15000):
    print(f"[*] Processing TXT: {txt_path} (Label: {label}, Limit: {max_lines})...")
    count = 0
    try:
        with open(txt_path, "r", encoding="utf-8") as infile, open(out_file, "a", encoding="utf-8") as outfile:
            for line in infile:
                if count >= max_lines:
                    break
                
                domain = line.strip()
                if domain:
                    features = extract_features(domain)
                    outfile.write(f"{label},{','.join(map(str, features))}\n")
                    count += 1
        print(f"  -> Extracted {count} records.")
    except Exception as e:
        print(f"[!] Error: {e}")

# ==========================================
# 4. MAIN FACTORY
# ==========================================
def build_dataset_from_cic():
    output_filename = "cic_unified_features.txt"
    
    if os.path.exists(output_filename):
        os.remove(output_filename)
        
    print(f"[*] Building PURE Dataset from CIC-DNS-EXF-2021 into '{output_filename}'...\n")

    # Take all PCAP files from CIC-DNS-EXF-2021 and extract features, while applying noise filtering to malware samples
    malware_pcaps = [
        "Attacks/light_audio.pcap",
        "Attacks/light_compressed.pcap",
        "Attacks/light_exe.pcap",
        "Attacks/light_image.pcap",
        "Attacks/light_text.pcap",
        "Attacks/light_video.pcap"
    ]
    
    benign_items = [
        "Benign/benign.pcap",
        "Benign/domains.txt"
    ]

    # 1. Extract Malware (Label 1)
    for pcap in malware_pcaps:
        if os.path.exists(pcap):
            process_pcap_file(pcap, 1, output_filename)
        else:
            print(f"[!] Warning: File not found - {pcap}")

    print("-" * 40)

    # 2. Extract Benign (Label 0)
    for item in benign_items:
        if os.path.exists(item):
            if item.endswith(".pcap"):
                process_pcap_file(item, 0, output_filename)
            elif item.endswith(".txt"):
                # Adjust max_lines if needed 
                process_txt(item, 0, output_filename, max_lines=15000) 
        else:
            print(f"[!] Warning: File not found - {item}")
            
    print("\n[+] Dataset extraction complete! Train your AI with 'cic_unified_features.txt'")

if __name__ == "__main__":
    build_dataset_from_cic()