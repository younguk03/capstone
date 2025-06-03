# from flask import Flask, render_template, request, jsonify
# import re
# import os
#
# app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
#
# # Route for the home page
# @app.route('/')
# def index():
#     return render_template('frontpage.html')
#
#
# # Route to validate SQL query
# @app.route('/validate', methods=['POST'])
# def validate_query():
#     query = request.json.get('query')
#     result = {}
#
#     # Basic SQL Injection validation pattern (for demonstration)
#     sql_injection_pattern = re.compile(r"(union|select|drop|--|#|\*|insert|update|delete|;|\\)", re.IGNORECASE)
#
#     if sql_injection_pattern.search(query):
#         result['safe'] = False
#         result['message'] = 'SQL Injection Detected!'
#         result['dl_score'] = 0.1  # You can adjust this with real model score
#     else:
#         result['safe'] = True
#         result['message'] = 'SQL Query is Safe.'
#         result['dl_score'] = 0.9  # You can adjust this with real model score
#
#     return jsonify(result)
#
# if __name__ == '__main__':
#     app.run(debug=True)
