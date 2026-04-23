import json
import time
import os
import math
import re  # Added for regex operations (Digit Ratio)
import tldextract
import numpy as np
from collections import Counter
from sklearn.tree import DecisionTreeClassifier

# ==========================================
# PART 1: FEATURE EXTRACTION
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
    """Extract [Sub_Length, Entropy, Digit_Ratio, Root_Length] from FQDN"""
    require = tldextract.extract(fqdn)
    subdomain = require.subdomain
    root_domain = require.domain

    root_length = len(root_domain)

    # If there is no subdomain, treat it as safe
    if not subdomain:
        return 0, 0.0, 0.0, root_length

    length = len(subdomain)
    entropy = calculate_entropy(subdomain)

    # Calculate Digit Ratio to identify encoded payloads (Base32/64)
    digit_count = len(re.findall(r'\d', subdomain))
    digit_ratio = round(digit_count / length, 3)

    return length, entropy, digit_ratio, root_length

# ==========================================
# PART 2: MACHINE LEARNING TRAINING (ID3)
# ==========================================
def train_ai_model():
    print("[*] Initializing and training the Decision Tree (ID3) model...")

    # Updated Mock dataset with 4 features:
    # [Subdomain_Length, Entropy, Digit_Ratio, Root_Domain_Length]
    X_train = np.array([
        # Label 0: Clean Traffic (Meaningful words, low digits, normal root length)
        [0, 0.0, 0.0, 6], [3, 1.5, 0.0, 8], [10, 2.1, 0.1, 12], [5, 1.8, 0.0, 9], [12, 2.5, 0.05, 15],
        # Label 1: Malicious Traffic (Long subdomains, high entropy, high digit ratio)
        [25, 4.2, 0.4, 7], [30, 4.5, 0.5, 10], [40, 4.8, 0.6, 6], [55, 4.9, 0.45, 8], [18, 4.1, 0.5, 5]
    ])

    # Corresponding labels: 0 = SAFE, 1 = MALWARE
    y_train = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

    # Initialize Decision Tree algorithm with 'entropy' criterion (ID3/C4.5 algorithm)
    model = DecisionTreeClassifier(criterion="entropy", max_depth=3)
    model.fit(X_train, y_train)

    print("[+] Training successful! AI is ready with 4 advanced features.\n" + "="*50)
    return model

# ==========================================
# PART 3: ACTIVE RESPONSE
# ==========================================
def block_attacker_ip(ip_address):
    print(f"\n[!!!] ACTIVE RESPONSE TRIGGERED [!!!]")
    print(f"[*] Executing iptables to block IP: {ip_address}")

    # Fixed syntax to execute OS command properly
    os.system(f"sudo iptables -A FORWARD -s {ip_address} -j DROP")
    print(f"[+] Successfully isolated IP: {ip_address}\n")

# ==========================================
# PART 4: REAL-TIME DPI ENGINE
# ==========================================
def monitor_suricata_logs(log_path, ai_model):
    print(f"[*] Listening to Suricata data stream: {log_path} ...")

    try:
        with open(log_path, 'r') as f:
            # Move the pointer to the end of the file (similar to 'tail -f' command)
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1) # Sleep for 0.1s if there is no new log
                    continue

                try:
                    # Parse the JSON log line from Suricata
                    log_data = json.loads(line)

                    # Only care about DNS protocol packets
                    if log_data.get("event_type") == "dns":
                        dns_info = log_data.get("dns", {})
                        query_type = dns_info.get("type")

                        # Only consider domain queries (e.g., A record, TXT, CNAME)
                        if query_type in ["query", "answer", "request", "response"]:
                            
                            # --- FIX FOR SURICATA 8.0 JSON STRUCTURE ---
                            domain_queried = dns_info.get("rrname", "")
                            
                            if not domain_queried and "queries" in dns_info and len(dns_info["queries"]) > 0:
                                domain_queried = dns_info["queries"][0].get("rrname", "")
                                
                            if not domain_queried:
                                continue # Skip empty/junk logs
                                
                            src_ip = log_data.get("src_ip", "")
                            # --- END FIX ---

                            # 1. Feature Extraction (Now receiving 4 parameters)
                            length, entropy, digit_ratio, root_length = extract_features(domain_queried)

                            # Skip very short domains to optimize performance (Currently disabled for testing)
                            #if length < 5:
                            #    continue

                            # 2. Feed to AI for prediction
                            features = np.array([[length, entropy, digit_ratio, root_length]])
                            prediction = ai_model.predict(features)[0] # Returns 0 or 1

                            # 3. Decision Making
                            if prediction == 1:
                                print(f"🚨 [MALWARE ALERT] DNS Tunneling Detected!")
                                print(f"   -> Source IP: {src_ip}")
                                print(f"   -> Domain: {domain_queried}")
                                print(f"   -> Metrics: SubLen={length}, Ent={entropy}, Digits={digit_ratio}, RootLen={root_length}")

                                # Block IP immediately
                                block_attacker_ip(src_ip)
                            else:
                                # Clean traffic passing through
                                print(f"✅ [SAFE] {domain_queried} (Ent: {entropy}, Digits: {digit_ratio})")
                                pass

                except json.JSONDecodeError:
                    continue # Skip if the log line has formatting errors

    except KeyboardInterrupt:
        print("\n[*] DPI monitoring system terminated.")
    except FileNotFoundError:
        print(f"[!] Error: Log file not found at {log_path}")
        print("[!] Ensure Suricata is running and generating the eve.json file")

# ==========================================
# MAIN FUNCTION
# ==========================================
if __name__ == "__main__":
    # Install required libraries: pip install scikit-learn numpy tldextract

    # 1. Initialize the "Brain" (AI Model)
    model = train_ai_model()

    # 2. Enable the "Eyes" (Point to Suricata's log file)
    # Note: Adjust this path to match your Ubuntu Server environment
    suricata_log_file = "/var/log/suricata/eve.json"

    # 3. Run the system
    monitor_suricata_logs(suricata_log_file, model)