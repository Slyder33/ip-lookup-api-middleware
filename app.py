from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/lookup-ip', methods=['POST'])
def lookup_ip():
    try:
        ip_data = request.get_json()
        ip_address = ip_data.get('ip')

        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400

        # Use ipwho.is for location lookup
        response = requests.get(f"https://ipwho.is/{ip_address}")
        if response.status_code != 200:
            return jsonify({'error': 'Failed to fetch data from ipwho.is'}), 502

        data = response.json()

        result = {
            "ip": ip_address,
            "country_name": data.get("country", "N/A"),
            "country_code": data.get("country_code", "N/A"),
            "region_name": data.get("region", "N/A"),
            "city": data.get("city", "N/A")
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
