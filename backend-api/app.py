from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/hello")
def hello():
    return jsonify({
        "message": "Hello from backend API",
        "user": request.headers.get("X-Forwarded-User"),
        "email": request.headers.get("X-Forwarded-Email")
    })

@app.route("/")
def index():
    return jsonify({
        "message": "OAuth2 Proxy is working",
        "user": request.headers.get("X-Forwarded-User"),
        "email": request.headers.get("X-Forwarded-Email")
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
