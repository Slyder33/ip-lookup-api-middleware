from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Constants for scoring
SCORE_WEIGHTS = {
    "spoofed_email": 3,
    "dkim_fail": 2,
    "spf_fail": 2,
    "domain_mismatch": 2,
    "phishing_service": 3,
    "geo_suspicious": 2
}

# Known suspicious countries for certain domains (e.g., US bank shouldn't send emails from Germany)
SUSPICIOUS_GEO = {
    "chase.com": ["Germany", "Russia", "China"]
}

def fetch_ip_data(ip):
    url = f"https://ipwho.is/{ip}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else {}

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

    # Geographic suspicion check
    domain = data.get("real_email", "").split("@")[-1].lower()
    country = data.get("country_name", "")
    if domain in SUSPICIOUS_GEO and country in SUSPICIOUS_GEO[domain]:
        score += SCORE_WEIGHTS["geo_suspicious"]
        notes.append(f"Suspicious geography: {country}")

    return score, notes

def determine_verdict(score):
    if score >= 6:
        return "Spoofed / Suspicious Header"
    elif score >= 3:
        return "Possibly Spoofed"
    else:
        return "Likely Legit"

@app.route("/lookup-ip", methods=["POST"])
def lookup_ip():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP address"}), 400

    ip_info = fetch_ip_data(ip)
    if not ip_info.get("success"):
        return jsonify({"error": "Failed to retrieve IP info"}), 500

    result = {
        "ip": ip_info.get("ip", "N/A"),
        "country_name": ip_info.get("country", "N/A"),
        "country_code": ip_info.get("country_code", "N/A"),
        "region_name": ip_info.get("region", "N/A"),
        "city": ip_info.get("city", "N/A"),
        "real_email": data.get("real_email", "N/A"),
        "spoofed": data.get("spoofed", False),
        "sender_name": data.get("sender_name", "N/A"),
        "spoofed_email": data.get("spoofed_email", "N/A"),
        "dkim_status": data.get("dkim_status", "N/A"),
        "spf_status": data.get("spf_status", "N/A"),
        "domain_match": data.get("domain_match", False),
        "phishing_check": data.get("phishing_check", False)
    }

    score, notes = score_header(result)
    result["verdict"] = determine_verdict(score)
    result["suspicion_score"] = score
    result["suspicion_notes"] = notes

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
