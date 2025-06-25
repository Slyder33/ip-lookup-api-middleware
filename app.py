from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return "IP Lookup API is running!"

@app.route('/lookup-ip', methods=['POST'])
def lookup_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    response = requests.get(f"https://api.iplocation.net/?cmd=ip-country&ip={ip}")
    return jsonify(response.json())
