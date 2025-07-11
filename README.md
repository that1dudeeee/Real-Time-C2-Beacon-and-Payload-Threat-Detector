# Real-Time-C2-Beacon-and-Payload-Threat-Detector
Detects C2 beaconing, base64 payloads, reverse shells, suspicious User-Agents, and traffic to known C2 ports. Uses Scapy to sniff TCP traffic, analyzes payloads with regex, checks GeoIP/ISP, and can auto-block IPs with iptables. Real-time alerts via notify-send. Designed for Blue Team network monitoring.
