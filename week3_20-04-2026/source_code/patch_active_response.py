def block_attacker_ip(ip_address):
    # Whitelist to prevent self-blocking
    GATEWAY_IP = "192.168.50.1"
    
    print(f"\n[!!!] ACTIVE RESPONSE TRIGGERED [!!!]")
    
    if ip_address == GATEWAY_IP:
        print(f"[*] WARNING: Ignored Gateway IP {ip_address} to prevent self-lockout.")
        return # Do not block the gateway IP to avoid locking ourselves out of the network
        
    print(f"[*] Executing iptables to block IP: {ip_address}")

    # Drop forwarded and direct traffic
    os.system(f"sudo iptables -A FORWARD -s {ip_address} -j DROP")
    
    # Block direct communication with Gateway (Block nslookup)
    os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    
    print(f"[+] Successfully isolated IP: {ip_address}\n")