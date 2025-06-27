from flask import Flask, request, jsonify
import requests
from email.parser import Parser
import re
import os

GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

app = Flask(__name__)

# Scoring weights
SCORE_WEIGHTS = {
    "spoofed_email": 3,
    "dkim_fail": 2,
    "spf_fail": 2,
    "domain_mismatch": 2,
    "phishing_service": 3,
    "geo_suspicious": 2
}

SUSPICIOUS_GEO = {
    "chase.com": ["Germany", "Russia", "China"]
}

# 🌎 IP Geolocation Lookup
def fetch_ip_data(ip):
    url = f"https://ipwho.is/{ip}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else {}
from ipwhois import IPWhois
import socket

def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "asn": res.get("asn", "N/A"),
            "asn_description": res.get("asn_description", "N/A"),
            "network_name": res.get("network", {}).get("name", "N/A"),
        }
    except Exception:
        return {"asn": "N/A", "asn_description": "N/A", "network_name": "N/A"}

def get_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "N/A"

def is_suspicious_tld(email):
    risky_tlds = ['.tk', '.ru', '.cn', '.ml', '.ga', '.cf']
    domain = email.split('@')[-1].lower()
    return any(domain.endswith(tld) for tld in risky_tlds)

# 🧠 Verdict Logic
def determine_verdict(score):
    if score >= 6:
        return "Spoofed / Suspicious Header"
    elif score >= 3:
        return "Possibly Spoofed"
    else:
        return "Likely Legit"

# 🧮 Heuristic Scoring
def score_header(data):
    suspicion_score = 0
    notes = []

    sender_name = data.get("sender_name", "").lower()
    spf_status = data.get("spf_status", "")
    dkim_status = data.get("dkim_status", "")
    domain_match = data.get("domain_match", True)
    phishing_check = data.get("phishing_check", False)

    spammy_phrases = [
        "kindly review", "urgent", "update your account", "final notice",
        "action required", "verify", "invoice", "payment pending",
        "you have won", "click here", "immediate attention", "confirm now",
        "reset your password", "suspended", "security alert", "claim prize"
    ]

    if any(word in sender_name for word in spammy_phrases):
        suspicion_score += 4
        notes.append(f"Suspicious sender name: {data.get('sender_name', 'N/A')}")

    if spf_status.lower() != "pass":
        suspicion_score += 3
        notes.append("SPF failed")

    if dkim_status.lower() != "pass":
        suspicion_score += 3
        notes.append("DKIM failed")

    if not domain_match:
        suspicion_score += 2
        notes.append("From domain does not match originating domain")

    if phishing_check:
        suspicion_score += 2
        notes.append("IP is associated with known phishing services")

    # ✅ Add TLD check
    if is_suspicious_tld(data.get("real_email", "")):
        suspicion_score += 2
        notes.append("Suspicious TLD detected")

    # ✅ Add reverse DNS insight
    reverse_dns = get_reverse_dns(data.get("ip", ""))
    if reverse_dns != "N/A":
        notes.append(f"Reverse DNS: {reverse_dns}")
        if any(word in reverse_dns for word in ["compute", "amazonaws", "vultr", "ovh", "contabo"]):
            suspicion_score += 2
            notes.append("Reverse DNS points to cloud host (possible automation)")

    # ✅ Add ASN info
    asn_data = get_asn_info(data.get("ip", ""))
    notes.append(f"ASN: {asn_data['asn']} ({asn_data['asn_description']})")

    # ✅ Verdict here can be used but not returned (we’ll call determine_verdict separately)
    return suspicion_score, notes, determine_verdict(suspicion_score)

# 📬 Parse Email Header
def parse_header(raw_header):
    parsed = {
        "sender_name": "N/A", "real_email": "N/A",
        "spoofed_email": None, "spoofed": False,
        "ip": None, "dkim_status": "N/A",
        "spf_status": "N/A", "domain_match": False,
        "phishing_check": False
    }

    try:
        msg = Parser().parsestr(raw_header)

        from_hdr = msg.get("From", "")
        m = re.search(r'(?P<name>.*)?<(?P<email>[^>]+)>', from_hdr)
        if m:
            parsed["sender_name"] = m.group("name").strip().strip('"') or "N/A"
            parsed["real_email"] = m.group("email").strip()
        else:
            parsed["real_email"] = from_hdr.strip()

        if "@" in parsed["real_email"]:
            domain = parsed["real_email"].split("@")[1].lower()
            parsed["domain_match"] = domain in from_hdr.lower()
            if not parsed["domain_match"]:
                parsed["spoofed_email"] = parsed["real_email"]
                parsed["spoofed"] = True

        received = msg.get_all("Received", []) or []
        ip_pat = re.compile(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?')
        for line in received:
            ipm = ip_pat.search(line)
            if ipm:
                parsed["ip"] = ipm.group(1)
                break

        for auth_line in msg.get_all("Authentication-Results", []) or []:
            lower = auth_line.lower()
            if "spf=pass" in lower: parsed["spf_status"] = "Pass"
            if "spf=fail" in lower: parsed["spf_status"] = "Fail"
            if "dkim=pass" in lower: parsed["dkim_status"] = "Pass"
            if "dkim=fail" in lower: parsed["dkim_status"] = "Fail"

        if "knowbe4" in raw_header.lower():
            parsed["phishing_check"] = True

    except Exception as e:
        parsed["error"] = f"Header parse error: {str(e)}"

    return parsed

# 🔍 Google Safe Browsing Check
def check_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "email-header-sleuth", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(api_url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return bool(data.get("matches"))
    return False

# 🚀 Main Endpoint
@app.route("/", methods=["POST"])
def analyze():
    data = request.get_json()
    raw_header = data.get("header")
    if not raw_header:
        return jsonify({"error": "Missing email header"}), 400

    parsed = parse_header(raw_header)
    ip_info = fetch_ip_data(parsed["ip"]) if parsed.get("ip") else {}
    merged = {**parsed, **ip_info}

    # Check links using Safe Browsing
    if "urls" in merged:
        malicious_urls = [url for url in merged["urls"] if check_safe_browsing(url)]
        if malicious_urls:
            merged["malicious_urls"] = malicious_urls

    # Score it!
    score, notes, verdict = score_header(merged)
    merged["suspicion_score"] = score
    merged["suspicion_notes"] = notes

    if "malicious_urls" in merged and merged["malicious_urls"]:
        merged["suspicion_notes"].append("Malicious URL(s) detected via Google Safe Browsing.")
        merged["suspicion_score"] += len(merged["malicious_urls"])

    merged["verdict"] = determine_verdict(merged["suspicion_score"])

    return jsonify(merged)

if __name__ == "__main__":
    app.run(debug=True)
