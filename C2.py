#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import re
import subprocess
import requests

BAD_COUNTRIES = ["china", "russia", "iran", "north korea"]
BAD_ISP_KEYWORDS = ["tor", "unknown", "proxy", "vpn"]
connect = defaultdict(list)

def geo(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        return (
            data.get("country", "").lower(),
            data.get("city", ""),
            data.get("isp", "").lower()
        )
    except Exception as e:
        print(f"[!] Geo lookup failed for {ip}: {e}")
        return "unknown", "unknown", "unknown"

def ban(ip):
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Banned IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to ban IP: {ip}")

def alert(title):
    try:
        subprocess.run(["notify-send", title])
    except:
        pass  

def detect_payload(raw, dst):
    findings = []
    country, city, isp = geo(dst)

    def tag(msg):
        findings.append(msg)
        print(f"[!] {msg}")
        print(f"    └─ Location: {country.title()}, {city}")
        print(f"    └─ ISP: {isp}")

        if country in BAD_COUNTRIES:
            print("    └─ [!!] Blacklisted Country")
        if any(keyword in isp for keyword in BAD_ISP_KEYWORDS):
            print("    └─ [!!] Suspicious ISP")

    if re.search(r'[A-Za-z0-9+/=]{12,}', raw):
        tag("Base64 encoding / firewall bypass activity")
        alert("BYPASS FIREWALL DETECTED")

    if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}', raw):
        tag("High-entropy encoded payload")
        alert("ENCODED PAYLOAD FOUND")

    if re.search(r'User-Agent:\s*(curl|python|PowerShell|^$)', raw):
        tag("Suspicious User-Agent")
        alert("SUSPICIOUS AGENT FOUND")

    if re.search(r'(bash\s+-i|nc\s+-e|python\s+-c|/dev/tcp/)', raw):
        tag("Reverse shell pattern detected")
        alert("REVERSE PAYLOAD FOUND")

    if findings:
        try:
            choice = input("[?] Action? (1) BAN (2) IGNORE: ").strip()
            if choice == "1":
                ban(dst)
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            exit(0)

def C2(packet):
    if IP in packet and TCP in packet:
        dst = packet[IP].dst
        now = time.time()
        connect[dst].append(now)

        
        if len(connect[dst]) >= 3:
            times = connect[dst][-3:]
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            avg = sum(deltas) / len(deltas)

            if all(abs(x - avg) < 2 for x in deltas):
                print(f"\n[!] Beaconing detected to {dst} every ~{int(avg)}s")

                raw = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                detect_payload(raw, dst)
        
        if packet[TCP].dport in [1337, 9001] and len(packet) < 100:
            print(f"[!] C2-like traffic: {dst}:{packet[TCP].dport} (small packet)")

def main():
    print("[*] Starting C2 & Payload Monitor...")
    try:
        sniff(filter="tcp", prn=C2, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

if __name__ == "__main__":
    main()
