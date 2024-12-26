from flask import Flask, request, jsonify
from owasptop10.sql_injection import detect_sql_injection
from owasptop10.xss import detect_xss
from owasptop10.csrf import detect_csrf

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    scan_type = data.get("type")
    content = data.get("content")

    results = []

    if scan_type == "code":
        results.extend(detect_sql_injection(content))
        results.append(detect_xss(content))
        results.append(detect_csrf(content))
    elif scan_type == "link":
        results.extend(detect_sql_injection(content))
        results.append(detect_xss(content))
        results.append(detect_csrf(content))

    return jsonify({"results": results})


if __name__ == '__main__':
    app.run(debug=True)