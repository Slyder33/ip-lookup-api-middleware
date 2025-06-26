from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/lookup-ip', methods=['POST'])
def lookup_ip():
    try:
        data = request.get_json()
        ip = data.get("ip")

        if not ip:
            return jsonify({"error": "Missing 'ip' in request body"}), 400

        ipwho_url = f"https://ipwho.is/{ip}"
        response = requests.get(ipwho_url)

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch IP info"}), 502

        ip_data = response.json()

        result = {
            "ip": ip_data.get("ip", "N/A"),
            "country_name": ip_data.get("country", "N/A"),
            "country_code": ip_data.get("country_code", "N/A"),
            "region_name": ip_data.get("region", "N/A"),
            "city": ip_data.get("city", "N/A")
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
