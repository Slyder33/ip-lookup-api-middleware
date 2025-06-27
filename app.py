from flask import Flask, request, jsonify
import requests
from email.parser import Parser
import re

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

# Optional domain-specific geo-suspicion logic
SUSPICIOUS_GEO = {
    "chase.com": ["Germany", "Russia", "China"]
}

# 🌎 IP Geolocation Lookup
def fetch_ip_data(ip):
    url = f"https://ipwho.is/{ip}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else {}

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
    score = 0
    notes = []

    if data.get("spoofed"):
        score += SCORE_WEIGHTS["spoofed_email"]
        notes.append("Spoofed sender")

    if data.get("dkim_status", "").lower() == "fail":
        score += SCORE_WEIGHTS["dkim_fail"]
        notes.append("DKIM failed")

    if data.get("spf_status", "").lower() == "fail":
        score += SCORE_WEIGHTS["spf_fail"]
        notes.append("SPF failed")

    if not data.get("domain_match"):
        score += SCORE_WEIGHTS["domain_mismatch"]
        notes.append("Domain mismatch")

    if data.get("phishing_check"):
        score += SCORE_WEIGHTS["phishing_service"]
        notes.append("Known phishing service")

    domain = data.get("real_email", "").split("@")[-1].lower()
    country = data.get("country_name", "")
    if domain in SUSPICIOUS_GEO and country in SUSPICIOUS_GEO[domain]:
        score += SCORE_WEIGHTS["geo_suspicious"]
        notes.append(f"Suspicious geography: {country}")

    return score, notes

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

        # Check for training domains
        if "knowbe4" in raw_header.lower():
            parsed["phishing_check"] = True

    except Exception as e:
        parsed["error"] = f"Header parse error: {str(e)}"

    return parsed

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

    score, notes = score_header(merged)
    merged["suspicion_score"] = score
    merged["suspicion_notes"] = notes
    merged["verdict"] = determine_verdict(score)

    return jsonify(merged)

if __name__ == "__main__":
    app.run(debug=True)
