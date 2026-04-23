#!/bin/bash
echo "[*] Start sending 5 clean domains..."
clean_domains="www.google.com www.vnexpress.net mail.yahoo.com chat.openai.com github.com"
for domain in $clean_domains; do
    echo " -> Asking $domain"
    nslookup $domain 192.168.50.1 > /dev/null
    sleep 2
done

echo "[*] Start sending 5 suspicious domains..."
for i in 1 2 3 4 5; do
    random_sub=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 20 | head -n 1)
    echo " -> Asking $random_sub.malware.local"
    nslookup "$random_sub.malware.local" 192.168.50.1 > /dev/null
    sleep 2
done
echo "[*] DONE!"
