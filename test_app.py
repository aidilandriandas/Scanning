#!/usr/bin/env python3
"""Simple vulnerable Flask app for testing the scanner"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable to XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(f'''
        <!DOCTYPE html>
        <html>
        <head><title>Search</title></head>
        <body>
            <h1>Search Results for: {query}</h1>
            <p>No results found.</p>
        </body>
        </html>
    ''')

# Vulnerable to SQL Injection (simulated)
@app.route('/user')
def user():
    user_id = request.args.get('id', '1')
    # Simulated SQL error message
    if "'" in user_id:
        return "SQL Error: You have an error in your SQL syntax near '\"'", 500
    return f"User ID: {user_id}"

# Directory traversal (simulated)
@app.route('/file')
def file_view():
    filename = request.args.get('name', 'index.html')
    if '../' in filename or '..\\' in filename:
        return "root:x:0:0:root:/root:/bin/bash", 200
    return "File content here"

# Open redirect
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url', '/')
    if url.startswith('http'):
        return '', 302, {'Location': url}
    return f"Redirecting to: {url}"

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Test App</title></head>
    <body>
        <h1>Vulnerable Test Application</h1>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/user?id=1">User (SQLi)</a></li>
            <li><a href="/file?name=index.html">File Viewer (Traversal)</a></li>
            <li><a href="/redirect?url=http://example.com">Redirect</a></li>
        </ul>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("Starting vulnerable test app on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
