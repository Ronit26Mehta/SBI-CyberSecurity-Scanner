from flask import Blueprint, jsonify, request
from app.utils.static_analysis import perform_static_analysis
from app.utils.dynamic_analysis import perform_dynamic_analysis

main_routes = Blueprint('main_routes', __name__)

@main_routes.route('/static-analysis', methods=['POST'])
def static_analysis():
    code = request.json.get('code')
    results = perform_static_analysis(code)
    return jsonify({"results": results})

@main_routes.route('/dynamic-analysis', methods=['POST'])
def dynamic_analysis():
    url = request.json.get('url')
    results = perform_dynamic_analysis(url)
    return jsonify({"results": results})