from flask import Blueprint, jsonify, request
from app.utils.dynamic_analysis import perform_dynamic_analysis

main_routes = Blueprint('main_routes', __name__)

@main_routes.route('/dynamic-analysis', methods=['POST'])
def dynamic_analysis():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400 
    
    results = perform_dynamic_analysis(url)
    return jsonify({"results": results})