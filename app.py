from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return "IP Lookup API is running!"

@app.route("/lookup-ip", methods=["POST"])
def lookup_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    response = requests.get(f"https://api.iplocation.net/?cmd=ip-country&ip={ip}")
    ip_data = response.json()

    return jsonify({
        "ip": ip_data.get("ip", "N/A"),
        "country_name": ip_data.get("country_name", "N/A"),
        "country_code": ip_data.get("country_code", "N/A"),
        "region_name": ip_data.get("region_name", "N/A"),
        "city": ip_data.get("city", "N/A")
    })

# No app.run() needed – Render uses gunicorn via render.yaml
