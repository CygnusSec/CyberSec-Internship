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

# Burst Detection Settings (Micro-slicing Evasion Mitigation)
THRESHOLD_BURST_HITS = 10    # Block if 10 unique subdomains to the SAME root domain...
THRESHOLD_BURST_WINDOW = 30.0 # ...within 30 seconds

# ---> Test: Volume Quota Settings (Low & Slow) <---
THRESHOLD_VOLUME_BYTES = 1000  # Block if total query volume exceeds 1000 bytes within the window

THRESHOLD_RISK_CRITICAL = 75   # Score >= 75: Block IP via iptables (RED)
THRESHOLD_RISK_WARNING = 40    # Score >= 40: Log as suspicious/alert (YELLOW)

# Global State Tracking
blocked_ips = set()
# Now stores tuples: { 'IP': [(timestamp, 'domain1'), (timestamp, 'domain2')] }
violation_history = defaultdict(list)
# Stores tuples for burst detection: { 'IP': [(timestamp, 'root_domain', 'subdomain')] }
volume_history = defaultdict(list)
volume_quota = defaultdict(int) # Tracks total query volume per IP for volume-based blocking

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

    # ==========================================
    # RESET ALL QUOTAS FOR THIS IP
    # ==========================================
    # Find all tuple keys (IP, Domain) that belong to this specific IP address
    keys_to_reset = [key for key in volume_quota.keys() if key[0] == ip_address]
    
    # Iterate and reset each domain quota for the unblocked host
    for key in keys_to_reset:
        volume_quota[key] = 0  # Clear accumulated bytes back to zero

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
def check_burst_and_block(ip_address, fqdn):
    current_time = time.time()

    # Extract root domain and subdomain
    ext = tldextract.extract(fqdn)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain

    if not subdomain or not root_domain:
        return False

    # 1. Log query for burst tracking
    volume_history[ip_address].append((current_time, root_domain, subdomain))

    # 2. Sliding Window: Remove old entries outside burst window
    volume_history[ip_address] = [
        (t, r, s) for t, r, s in volume_history[ip_address]
        if current_time - t <= THRESHOLD_BURST_WINDOW
    ]

    # 3. Count unique subdomains for the CURRENT root domain
    unique_subdomains = set(
        s for t, r, s in volume_history[ip_address]
        if r == root_domain
    )

    if len(unique_subdomains) >= THRESHOLD_BURST_HITS:
        current_quota = volume_quota[(ip_address, root_domain)] # Lấy dung lượng tích lũy ngầm
        print(f"\n[!!!] BURST ALERT: Micro-Slicing Evasion Detected!")
        print(f"[*] Target IP   : {ip_address} -> Destination Domain: {root_domain}")
        print(f"[*] Trigger     : Exceeded {THRESHOLD_BURST_HITS} unique subdomains within {THRESHOLD_BURST_WINDOW}s")
        print(f"[*] Log Context : Current Domain Volume: {current_quota}/{THRESHOLD_VOLUME_BYTES}B")
        print(f"[*] Last Domain: {fqdn}")

        block_attacker_ip(ip_address)

        # Cleanup to prevent double-triggering
        volume_history[ip_address] = [
            (t, r, s) for t, r, s in volume_history[ip_address]
            if r != root_domain
        ]
        return True

    return False

def check_volume_and_block(ip_address, fqdn):
    ext = tldextract.extract(fqdn)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain

    if not subdomain or not root_domain:
        return False

    # Calculate payload size (length of subdomain)
    payload_size = len(subdomain)
    
    # NEW CONCEPT: Track quota per (IP, Root Domain) pair instead of just IP
    tracking_key = (ip_address, root_domain)
    volume_quota[tracking_key] += payload_size

    # Check if quota exceeded for this SPECIFIC destination
    if volume_quota[tracking_key] >= THRESHOLD_VOLUME_BYTES:
        print(f"\n[!!!] QUOTA ALERT: Low & Slow Exfiltration Detected!")
        print(f"[*] Target IP   : {ip_address} -> Destination Domain: {root_domain}")
        print(f"[*] Trigger     : Exceeded data exfiltration quota limit.")
        print(f"[*] Log Context : Current Domain Volume: {volume_quota[tracking_key]}/{THRESHOLD_VOLUME_BYTES}B (BREACHED)")
        print(f"[*] Last Domain: {fqdn}")

        block_attacker_ip(ip_address)
        return True

    return False


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

    # Extract root domain for quota context
    ext = tldextract.extract(domain)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    current_quota = volume_quota[(ip_address, root_domain)]

    # Decision logic based on unique hits within the time window
    if current_unique_hits >= THRESHOLD_UNIQUE_HITS:
        print(f"\n[!!!] BEHAVIORAL ALERT: Sustained DNS Tunneling Attack Detected!")
        print(f"[*] Target IP   : {ip_address} -> Destination Domain: {root_domain}")
        print(f"[*] Trigger     : Hit {current_unique_hits}/{THRESHOLD_UNIQUE_HITS} unique high-entropy subdomains within {THRESHOLD_WINDOW}s")
        print(f"[*] Log Context : Current Domain Volume: {current_quota}/{THRESHOLD_VOLUME_BYTES}B")
        print(f"[*] Last Domain : {domain}")

        block_attacker_ip(ip_address)
        del violation_history[ip_address]
    else:
        print(f"\n⚠️  [SUSPICIOUS] AI/DPI Signature Matched. Tracking IP: {ip_address}")
        print(f"   -> Destination Domain: {root_domain}")
        print(f"   -> Metrics Context   : {metrics_str}")
        print(f"   -> Time Window Hit   : {current_unique_hits}/{THRESHOLD_UNIQUE_HITS} unique malicious domains within {THRESHOLD_WINDOW}s")
        print(f"   -> Log Context       : Current Domain Volume: {current_quota}/{THRESHOLD_VOLUME_BYTES}B")
        print(f"   -> Current Domain    : {domain}")

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
                            if (prediction == 0) and ((entropy >= 4.2 and length >= 30) or (length >= 60)):
                                is_heuristic_malware = True
                                print("\n[!] ML Bypassed. Heuristic Override Activated!")

                            # ==========================================
                            # DYNAMIC RISK SCORING ENGINE
                            # ==========================================
                            ext_log = tldextract.extract(domain_queried)
                            r_dom = f"{ext_log.domain}.{ext_log.suffix}" if ext_log.suffix else ext_log.domain
                            now = time.time()

                            # 1. Update state data for the current packet
                            # A. Update volumetric counter
                            volume_quota[(src_ip, r_dom)] += length
                            
                            # B. Update burst history window
                            volume_history[src_ip].append((now, r_dom, ext_log.subdomain))
                            volume_history[src_ip] = [(t, r, s) for t, r, s in volume_history[src_ip] if now - t <= THRESHOLD_BURST_WINDOW]
                            
                            # C. Update frequency history window
                            if prediction == 1 or is_heuristic_malware:
                                violation_history[src_ip].append((now, domain_queried))
                            violation_history[src_ip] = [(t, d) for t, d in violation_history[src_ip] if now - t <= THRESHOLD_WINDOW]

                            # 2. Calculate dynamic component scores
                            total_risk_score = 0

                            # Component A: Lexical Risk Evaluation (Max: 30)
                            lexical_score = 0
                            if prediction == 1:
                                lexical_score += 20  # Score from AI Model
                            if is_heuristic_malware:
                                lexical_score += 10  # Score from L7 Heuristic Override
                            total_risk_score += lexical_score

                            # Component B: Temporal/Burst Frequency Evaluation (Max: 35)
                            unique_subdomains = set(s for t, r, s in volume_history[src_ip] if r == r_dom)
                            temporal_score = min(len(unique_subdomains) * 4, 35)  # Scale score by unique hits
                            total_risk_score += temporal_score

                            # Component C: Volumetric Accumulation Evaluation (Max: 35)
                            current_volume = volume_quota[(src_ip, r_dom)]
                            volumetric_score = min(int((current_volume / THRESHOLD_VOLUME_BYTES) * 35), 35)
                            total_risk_score += volumetric_score

                            # ==========================================
                            # ACTION TIER ROUTING (ACTION MAPPING)
                            # ==========================================
                            domain_display = domain_queried

                            # TIER 1: RED ALERT (Critical Risk - Isolate Host)
                            if total_risk_score >= THRESHOLD_RISK_CRITICAL:
                                print(f"\n🔴 [!!!] CRITICAL RISK ALERT [{total_risk_score}/100] | IP: {src_ip}")
                                print(f"   -> Trigger: Cumulative Risk Score Breached Threshold")
                                print(f"   -> Context: Lexical={lexical_score}, Temporal={temporal_score}, Volume={volumetric_score} ({current_volume}B)")
                                print(f"   -> Last Domain: {domain_display}")
                                
                                block_attacker_ip(src_ip)  # Execute firewall block
                                
                                # Clear state for blocked IP to reset trackers
                                if src_ip in violation_history: del violation_history[src_ip]
                                volume_history[src_ip] = [(t, r, s) for t, r, s in volume_history[src_ip] if r != r_dom]

                            # TIER 2: YELLOW ALERT (Suspicious Behavior - Log and Monitor)
                            elif total_risk_score >= THRESHOLD_RISK_WARNING:
                                print(f"\n⚠️  [WARNING] SUSPICIOUS BEHAVIOR [{total_risk_score}/100] | IP: {src_ip}")
                                print(f"   -> Context: Lexical={lexical_score}, Temporal={temporal_score}, Volume={volumetric_score} ({current_volume}B)")
                                print(f"   -> Domain: {domain_display}")

                            # TIER 3: GREEN STATE (Normal Traffic - Allowed)
                            else:
                                print(f"\n✅ [SAFE] Traffic Cleared [{total_risk_score}/100] | IP: {src_ip} | Domain: {domain_display}")
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