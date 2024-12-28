from flask import Flask, jsonify, request
from flask_cors import CORS
import json
from owasp.scanner import EnhancedWebSecurityScanner

app = Flask(__name__)
CORS(app)  

scan_report = {}

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target_url = data.get('target_url')

        if not target_url:
            return jsonify({"error": "Target URL is required"}), 400

        scanner = EnhancedWebSecurityScanner(target_url)
        scanner.scan()

        global scan_report
        with open('security_report.json', 'r') as file:
            scan_report = json.load(file)

        return jsonify({"message": "Scan started. Please check the report."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/report', methods=['GET'])
def report():
    try:
        return jsonify(scan_report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)