from flask import Flask, request

app = Flask(__name__)

def format_auth_table():
    # gather authentication information from headers
    rows = []
    email = request.headers.get("X-Auth-Email")
    user = request.headers.get("X-Auth-User")
    token = request.headers.get("Authorization")
    cookie = request.headers.get("Cookie")

    if email:
        rows.append(f"<tr><td>Email</td><td>{email}</td></tr>")
    if user:
        rows.append(f"<tr><td>User</td><td>{user}</td></tr>")
    if token:
        rows.append(f"<tr><td>Bearer Token</td><td>{token}</td></tr>")
    if cookie:
        rows.append(f"<tr><td>Cookie</td><td>{cookie}</td></tr>")

    if not rows:
        return ""

    return f"""
    <h3>Authentication Info</h3>
    <table border="1" cellpadding="5" cellspacing="0">
      <tr><th>Type</th><th>Value</th></tr>
      {''.join(rows)}
    </table>
    """

@app.route('/')
def home():
    content = "<h1>Home for backend API</h1>"
    content += '<p><a href="/api/hello">Go to Hello Page</a></p>'
    content += format_auth_table()
    return content

@app.route('/api/hello')
def hello():
    content = "<h1>Hello from backend API</h1>"
    content += '<p><a href="/">Back to Home</a></p>'
    content += format_auth_table()
    return content

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
