#!/bin/bash
TARGET="localhost"
echo "Starting LLOYD stress test against $TARGET..."
if ! command -v mosquitto_pub &> /dev/null; then sudo apt-get install -y mosquitto-clients; fi
for i in {1..50}; do
   echo "[*] Attack packet $i sent..."
   (echo "USER admin"; echo "PASS wrong") | nc -w 1 $TARGET 1883 &
   sleep 0.1
done
echo "Attack burst complete. Check LLOYD logs."