import json
import threading
import time
import os
import math
import re
import tldextract
import subprocess
import sys
import numpy as np
import pickle

from collections import Counter, defaultdict

# ==========================================
# CONFIGURATION & THRESHOLDS
# ==========================================
BLOCK_DURATION = 60
GATEWAY_IP = "192.168.50.1"

# Behavioral Analysis Settings
THRESHOLD_UNIQUE_HITS = 3    # Block if 3 DIFFERENT malicious domains are queried
THRESHOLD_WINDOW = 20.0      # Increased window to 20s to account for DNS timeouts

# Global State Tracking
blocked_ips = set()
# Now stores tuples: { 'IP': [(timestamp, 'domain1'), (timestamp, 'domain2')] }
violation_history = defaultdict(list)

# ==========================================
# PART 1: FEATURE EXTRACTION (Hybrid DPI)
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



# --- MAP STRING RRTYPE TO EMPIRICAL WEIGHT ---
def get_rrtype_weight(rrtype_str):
    rrtype_str = str(rrtype_str).upper()
    if rrtype_str == "PTR": return 3.25
    elif rrtype_str == "TXT": return 3.04
    elif rrtype_str == "ANY": return 2.98
    elif rrtype_str == "AAAA": return 2.55
    elif rrtype_str == "SRV": return 2.05
    elif rrtype_str == "A": return 0.02
    return 1.0  # Default for CNAME, MX, etc.

# --- EXTRACT 5-DIMENSIONAL FEATURES ---
def extract_features(fqdn, rrtype_str="A"):
    fqdn = str(fqdn).strip()
    if fqdn.endswith('.'):
        fqdn = fqdn[:-1]
        
    require = tldextract.extract(fqdn)
    subdomain = require.subdomain
    
    if not subdomain:
        return [0, 0.0, 0.0, 0.0, 0.0]

    length = len(subdomain)
    entropy = calculate_entropy(subdomain)
    
    digit_count = len(re.findall(r'\d', subdomain))
    digit_ratio = round(digit_count / length, 3) if length > 0 else 0.0

    type_weight = get_rrtype_weight(rrtype_str)

    consonant_count = len(re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]', subdomain))
    consonant_ratio = round(consonant_count / length, 3) if length > 0 else 0.0

    return [length, entropy, digit_ratio, type_weight, consonant_ratio]

# ==========================================
# PART 2: MODEL LOADING
# ==========================================
def load_ai_model():
    print("[*] Initializing AI Engine (Hybrid Lexical & Unique Behavioral)...")
    try:
        with open('ai_model_id3.pkl', 'rb') as f:
            model = pickle.load(f)
        print("[+] Model loaded successfully! System is ready for deployment.\n" + "="*50)
        return model
    except FileNotFoundError:
        print("[!] ERROR: File 'ai_model_id3.pkl' not found.")
        exit()

# ==========================================
# PART 3: ACTIVE RESPONSE (Firewall)
# ==========================================
def unblock_ip(ip_address):
    print(f"\n[*] Penalty timeout reached. Restoring access for IP: {ip_address} ...")
    os.system(f"sudo iptables -D FORWARD -s {ip_address} -j DROP")
    os.system(f"sudo iptables -D INPUT -s {ip_address} -j DROP")

    if ip_address in blocked_ips:
        blocked_ips.remove(ip_address)

    print(f"[+] Successfully unblocked IP: {ip_address}")
    print("-" * 50)

def block_attacker_ip(ip_address):
    if ip_address == GATEWAY_IP:
        return

    if ip_address in blocked_ips:
        return

    print(f"\n[!!!] CRITICAL: ACTIVE RESPONSE TRIGGERED [!!!]")
    print(f"[*] Executing iptables to isolate IP: {ip_address} for {BLOCK_DURATION} seconds")

    os.system(f"sudo iptables -I FORWARD 1 -s {ip_address} -j DROP")
    os.system(f"sudo iptables -I INPUT 1 -s {ip_address} -j DROP")

    blocked_ips.add(ip_address)
    print(f"[+] Network isolation complete for IP: {ip_address}")

    timer = threading.Timer(BLOCK_DURATION, unblock_ip, args=[ip_address])
    timer.start()

# ==========================================
# PART 4: BEHAVIORAL ENGINE (Unique Domain Logic)
# ==========================================
def check_frequency_and_block(ip_address, domain, metrics_str):
    current_time = time.time()

    # 1. Log timestamp AND the specific domain
    violation_history[ip_address].append((current_time, domain))

    # 2. Sliding Window: Remove entries older than THRESHOLD_WINDOW
    violation_history[ip_address] = [
        (t, d) for t, d in violation_history[ip_address]
        if current_time - t <= THRESHOLD_WINDOW
    ]

    # 3. UNIQUE Domain Counter (Solves A/AAAA duplicates & Retries)
    unique_domains = set(d for t, d in violation_history[ip_address])
    current_unique_hits = len(unique_domains)

    if current_unique_hits >= THRESHOLD_UNIQUE_HITS:
        print(f"\n[!!!] BEHAVIORAL ALERT: Sustained DNS Tunneling Attack Detected!")
        print(f"[*] Target IP: {ip_address} | Trigger: {current_unique_hits} UNIQUE high-entropy payloads within {THRESHOLD_WINDOW}s")
        print(f"[*] Last Offending Payload: {domain}")

        block_attacker_ip(ip_address)
        del violation_history[ip_address]
    else:
        print(f"⚠️  [SUSPICIOUS] AI Signature Matched. Tracking IP: {ip_address}")
        print(f"   -> Domain: {domain}")
        print(f"   -> Metrics: {metrics_str}")
        print(f"   -> Frequency: {current_unique_hits}/{THRESHOLD_UNIQUE_HITS} unique payloads within {THRESHOLD_WINDOW}s")

# ==========================================
# PART 5: SURICATA LOG PARSER
# ==========================================
def monitor_suricata_logs(log_path, ai_model):
    print(f"[*] Listening to Suricata data stream: {log_path} ...")

    try:
        with open(log_path, 'r') as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    log_data = json.loads(line)

                    if log_data.get("event_type") == "dns":
                        dns_info = log_data.get("dns", {})
                        query_type = dns_info.get("type")

                        if query_type in ["query", "request"]:
                            domain_queried = dns_info.get("rrname", "")

                            if not domain_queried and "queries" in dns_info and len(dns_info["queries"]) > 0:
                                domain_queried = dns_info["queries"][0].get("rrname", "")

                            if not domain_queried:
                                continue

                            src_ip = log_data.get("src_ip", "")

                            # --- EXTRACT DNS RECORD TYPE (L7 DPI) ---
                            rrtype = "A"  
                            if "queries" in dns_info and len(dns_info["queries"]) > 0:
                                rrtype = dns_info["queries"][0].get("rrtype", "A")

                            # Race Condition
                            if src_ip in blocked_ips:
                                continue
                            
                            # 5D Vector Analysis
                            length, entropy, digits, t_weight, cons_ratio = extract_features(domain_queried, rrtype)
                            features = np.array([[length, entropy, digits, t_weight, cons_ratio]])
                            
                            prediction = ai_model.predict(features)[0]

                            # --- Addition: DPI HEURISTIC OVERRIDE ---
                            # If ML model predicts SAFE (0) but we have a combination of strong heuristic indicators 
                            # Txt records, high entropy, and long length -> override to MALWARE (1) to prevent False Negatives.
                            # This is a critical safety net to catch evasive malware that may bypass the ML model, ensuring a strong security posture.
                            # 1. Payload entropy >= 4.2 AND length >= 30 (Highly suspicious for DGA-based tunneling)
                            # 2. Payload length >= 60 (Extremely long subdomains are often used in tunneling to maximize data exfiltration per query)
                            is_heuristic_malware = False
                            if (prediction == 0)and ((entropy >= 4.2 and length >= 30) or (length >= 60)):
                                is_heuristic_malware = True
                                print("[!] ML Bypassed. Heuristic Override Activated!") 

                            # --- BEHAVIORAL ROUTING & MITIGATION ---
                            if prediction == 1 or is_heuristic_malware:
                                metrics_str = f"Type: {rrtype}, Len: {length}, Ent: {entropy}, Cons: {cons_ratio}"
                                check_frequency_and_block(src_ip, domain_queried, metrics_str)
                            else:
                                print(f"✅ [SAFE] {domain_queried} (Type: {rrtype}, Len: {length}, Ent: {entropy}, Cons: {cons_ratio})")

                except json.JSONDecodeError:
                    continue

# --- Error handling for file access and graceful shutdown ---
    except KeyboardInterrupt:
        print("\n[!] User terminated the system (Ctrl+C). Initiating Graceful Shutdown...")

    # Emergency cleanup of iptables rules to prevent lockout
        if len(blocked_ips) > 0:
            print("[*] Cleaning up leftover iptables rules...")
            for ip in list(blocked_ips):
                try:
                    subprocess.run(
                        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                    print(f" [+] Emergency Unblocked IP: {ip}")
                except Exception as e:
                    pass
    
        print("[*] System safely offline. Goodbye!")
        sys.exit(0)

# --- ERROR HANDLING FOR LOG FILE ACCESS ---    
    except FileNotFoundError:
        print(f"[!] Error: Log file not found at {log_path}")
        sys.exit(1)

if __name__ == "__main__":
    model = load_ai_model()
    suricata_log_file = "/var/log/suricata/eve.json"
    monitor_suricata_logs(suricata_log_file, model)