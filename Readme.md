# Folder Structure for GitHub

```bash
/api-management-demo/
│
├── backend/                  # Simple API service
│   └── app.py / server.js
│
├── kong/tyk-config/          # Gateway configs and routes
│   └── kong.yaml / tyk.json
│
├── oauth2-proxy/             # Auth setup and provider config
│   └── oauth2-proxy.cfg
│
├── docker-compose.yml        # Or Kubernetes manifests
├── setup_guide.md            # How to run the demo
└── slides/                   # Final PPT or PDF

```



# Technical Plan

## ✅ Goal

Deploy an API with:

- **JWT Authentication** (via OAuth2 Proxy)
- **Rate Limiting** (via Kong or Tyk API Gateway)
- **Monitoring & Request Tracing** (using Postman)



## 🧱 Technology Stack Overview

| Component    | Tool                    | Purpose                                 |
| ------------ | ----------------------- | --------------------------------------- |
| API Gateway  | **Kong (OSS)** or Tyk   | Enforce auth and rate limiting policies |
| Auth Proxy   | **OAuth2 Proxy**        | Add JWT/OAuth2 authentication           |
| Backend API  | **Simple Flask app**    | Echo service for demo requests          |
| Kubernetes   | **Minikube / AKS**      | Orchestrate everything                  |
| Testing Tool | **Postman**             | Simulate client requests                |
| Monitoring   | **Kong Manager / Logs** | View request traffic and limits         |



------

## 🔧 Kubernetes-Based Architecture

Here’s a basic diagram of the setup:

```
[Postman / User]
        |
        v
 [Kong Gateway]  <-- Rate limiting, JWT auth policies
        |
        v
 [OAuth2 Proxy] <-- Issues JWT token via GitHub/Google
        |
        v
  [Flask API] <-- Just returns "Hello from backend!"
```

------

## 📁 Directory Structure for This Step

```
k8s-api-management/
├── backend-api/
│   ├── app.py                  # Flask backend
│   ├── Dockerfile
│   └── deployment.yaml         # K8s Deployment + Service
├── kong/
│   ├── kong-config.yaml        # Declarative config or ingress rules
│   └── kong-deployment.yaml
├── oauth2-proxy/
│   ├── oauth2-proxy.cfg
│   └── deployment.yaml
├── ingress/
│   └── ingress.yaml            # KongIngress or generic Ingress
├── scripts/
│   └── init.sh                 # Optional: init config using Admin API
└── README.md                   # Setup & instructions
```

------

## ✅ Step 1: Backend API Setup

Let's build the simple backend API first.

### `backend-api/app.py`

```python
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

```

### `backend-api/Dockerfile`

```dockerfile
FROM python:3.9
WORKDIR /app
COPY app.py .
RUN pip install flask
EXPOSE 5000
CMD ["python", "app.py"]
```

### `backend-api/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backend-api
  template:
    metadata:
      labels:
        app: backend-api
    spec:
      containers:
      - name: api
        image: your-dockerhub-username/backend-api:latest
        ports:
        - containerPort: 5000
---
apiVersion: v1
kind: Service
metadata:
  name: backend-api
spec:
  selector:
    app: backend-api
  ports:
    - protocol: TCP
      port: 80
      targetPort: 5000
```

**Note**: Replace `your-dockerhub-username` after pushing the image.

------

# ✅ **Step 2: Build and Push Docker Image to Docker Hub**

### 1. Save the Flask API and Dockerfile

Your directory:

```
k8s-api-management/
└── backend-api/
    ├── app.py
    └── Dockerfile
```

### 2. Build the Docker Image (from `backend-api` folder)

```bash
cd backend-api
docker build -t your-dockerhub-username/backend-api:latest .
```

### 3. Log in to Docker Hub

```bash
docker login
```

### 4. Push the Image

```bash
docker push your-dockerhub-username/backend-api:latest
```

✅ Confirm the image appears on your Docker Hub repository.

------

# ✅ Step 3: Deploy Backend API to Minikube

### 1. Start Minikube

```bash
minikube start --driver=docker
```

### 2. Apply the Deployment

```bash
kubectl apply -f backend-api/deployment.yaml --validate=false
```

### 3. Check Pods and Services

```bash
kubectl get pods
kubectl get svc
```

At this point, your backend should be running inside Kubernetes, but not yet exposed externally.

## Use `kubectl port-forward` (Best for quick testing)

### Step-by-step:

1. Find the Pod name:

```bash
kubectl get pods
```

1. Forward the Flask container's port (5000) to your local machine:

```bash
kubectl port-forward pod/<your-pod-name> 5000:5000
```

> Replace `<your-pod-name>` with the name from step 1 (e.g., `backend-api-6d44b98756-8x5p2`)

1. Open your browser or Postman and test:

```bash
http://localhost:5000/api/hello
```

✅ You’ll get: `{ "message": "Hello from the backend!" }`

------

# ✅ Step 4 (DB Mode): Register Service + Route in Kong

------

## 🧰 Prerequisites

Make sure these are installed:

- ✅ `kubectl`

- ✅ `helm`

  - On Windows (with Chocolatey)

    Open PowerShell as Administrator:

    ```powershell
    choco install kubernetes-helm
    ```

- ✅ `minikube`

## 🧱 What You'll Do

1. Reinstall Kong in **database mode**
2. Use **Kong’s Admin API** to:
   - Create a **Service**
   - Create a **Route**
   - Test the proxy

------

## 🔄 Step 4.1: Reinstall Kong in DB Mode

### 🧹 First, uninstall the DB-less Kong:

```bash
helm uninstall kong -n kong
```

### 🧱 Then install Kong with PostgreSQL enabled:

```powershell
helm install kong kong/kong -n kong --create-namespace `
  --set postgresql.enabled=true `
  --set postgresql.auth.username=kong `
  --set postgresql.auth.password=kongpass `
  --set postgresql.auth.database=kong `
  --set env.database=postgres `
  --set env.pg_user=kong `
  --set env.pg_password=kongpass `
  --set env.pg_database=kong `
  --set admin.enabled=true `
  --set admin.type=NodePort `
  --set proxy.type=NodePort `
  --set ingressController.enabled=false `
  --wait --timeout 5m
```

- This will:
  - Successfully complete the DB migration
  - Launch the Kong admin service
  - Let you access the Admin API to create services/routes via `curl`

------

## 🌐 Step 4.2: Get the Admin and Proxy URLs

```bash
minikube service kong-kong-admin -n kong --url
minikube service kong-kong-proxy -n kong --url
```

You’ll get:

- Admin: `http://127.0.0.1:xxxxx` ← used to POST configs
- Proxy: `http://127.0.0.1:yyyyy` ← used to test `/api/hello`

Test it (kong-admin):

```
curl.exe -k https://127.0.0.1:<admin-port>/services
```

You may see something like:

```
{"data":[],"next":null}
```

because there's no registered service.
If there's service and we want to clean them:

1. check which services we have:

```
curl.exe -k https://127.0.0.1:<admin-port>/services
```

2. for each service, check routes first, then delete:

   ```
   curl.exe -k https://127.0.0.1:<admin-port>/services/backend-api/routes
   ```

   get each route's ID, then delete：

   ```
   curl.exe -k -X DELETE https://127.0.0.1:<admin-port>/routes/f372164a-xxxx-xxxx
   ```

3. delete service:

   ```
   curl.exe -k -X DELETE https://127.0.0.1:<admin-port>/services/backend-api
   ```

   

------

## 🧪 Step 4.3: Register Your Backend Service

Use this command in PowerShell:

```powershell
curl.exe -k -i -X POST https://127.0.0.1:<admin-port>/services `
  --data "name=backend-api" `
  --data "url=http://backend-api.default.svc.cluster.local"
```

Replace `<admin-port>` with what you got from `minikube service kong-kong-admin`.

🔐 `-k` tells curl to skip SSL cert verification
 🌐 `https://` because your Kong Admin API is HTTPS-only
 🧱 This binds the `/api/hello` path to your backend service

When success, you will see something like:

```
HTTP/1.1 201 Created
Date: Tue, 13 May 2025 18:36:18 GMT
Content-Type: application/json; charset=utf-8
Connection: keep-alive
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Length: 398
X-Kong-Admin-Latency: 10
Server: kong/3.9.0

{"tls_verify":null,"created_at":1747161378,"updated_at":1747161378,"host":"backend-api.default.svc.cluster.local","name":"backend-api","id":"1d510c29-eb0f-4917-b483-c2c814a6fcd6","client_certificate":null,"retries":5,"path":null,"tls_verify_depth":null,"connect_timeout":60000,"enabled":true,"read_timeout":60000,"port":80,"write_timeout":60000,"protocol":"http","tags":null,"ca_certificates":null}
```



------

## 🧭 Step 4.4: Register Route for `/api/hello`

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/services/backend-api/routes `
  --data "paths[]=/" `
  --data "strip_path=false"
  
curl.exe -k -X POST https://127.0.0.1:<admin-port>/services/backend-api/routes `
  --data "paths[]=/api/hello" `
  --data "strip_path=false"
```

Tell Kong not to strip the path. That way, Kong forwards `/api/hello` → `/api/hello` (instead of `/`

### Double check：

### ✅ 1. Service in Kong is defined like this:

```powershell
curl.exe -k https://127.0.0.1:<admin-port>/services
```

You should see:

```json
{
  "protocol": "http",
  "host": "backend-api.default.svc.cluster.local",
  "port": 80,
  "path": null
}
```

------

### ✅ 2. Route is configured with `strip_path: false`

Check:

```bash
curl.exe -k https://127.0.0.1:<admin-port>/routes
```

You should see something like:

```json
"paths": ["/api/hello"],
"strip_path": false
```

------

## 🚀 Step 4.5: Test the API

Now test through Kong’s proxy:

```powershell
curl.exe http://127.0.0.1:<proxy-port>/api/hello
```

You should see:

```json
{"message": "Hello from the backend!"}
```

## ✅ How to Test `/api/hello` in Postman

### 🔧 1. Open Postman and create a new request

- Click **+ New Tab**

- Set **Request Type** to `GET`

- Enter the full URL:

  ```
  http://127.0.0.1:<proxy-port>/api/hello
  ```

> Replace `<proxy-port>` with your actual Kong proxy port. You can get it by running:

```bash
minikube service kong-kong-proxy -n kong --url
```

E.g., if it returns `http://127.0.0.1:31234`, then your full URL in Postman is:

```bash
http://127.0.0.1:31234/api/hello
```

------

### 🧪 2. Click **Send**

- If everything is working, you should see:

```json
{"message": "Hello from the backend!"}
```



# ✅ Step 5: Add Plugins to Secure and Scale Your API (DB Mode)

------

## 🎯 Objective

Now that Kong is successfully routing requests to your Flask backend, we’ll use the **Admin API** to:

1. Apply a **global rate-limiting** plugin to the `/api/hello` route
2. (Optional later) Add **JWT-based authentication** for per-user access control

------

## 🧪 Step 5.1: Add Global Rate Limiting Plugin

This limits how many times **anyone** can call the route.

------

### ✅ Step 1: Find your route ID

Run:

```powershell
curl.exe -k https://127.0.0.1:<admin-port>/routes
```

Look for the `id` of the route with:

```json
"paths": ["/api/hello"],
"strip_path": false
```

Let's assume it's:

```
f372164a-70d3-40a6-931e-dc59284a3988
```

------

### ✅ Step 2: Add the rate-limiting plugin

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins `
  --data "name=rate-limiting" `
  --data "config.minute=5" `
  --data "config.policy=local"
```

> 🔒 This allows **5 requests per minute total** across all clients.
>  🧠 `policy=local` stores counters in Kong memory (fine for demo).

------

### ✅ Step 3: Test rate limit is working

1. Run this 5 times:

```powershell
curl.exe http://127.0.0.1:<proxy-port>/api/hello
```

1. On the 6th request, you should get:

```http
HTTP/1.1 429 Too Many Requests
```

Headers like:

```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
Retry-After: 60
```

------

## 📝 Step 5 Summary

| What You Did               | Why It Matters                                       |
| -------------------------- | ---------------------------------------------------- |
| Added rate limiting plugin | Protects backend from overuse or DDoS                |
| Applied via Admin API      | Matches how many real-world teams manage API configs |
| Configured per-route       | Could be adjusted per user or service later          |



# ✅ Step 6 (Revised): Add JWT Authentication with Per-User Rate Limiting (DB Mode)

## 🎯 Objective

Enhance API security by requiring clients to:

1. Authenticate using **JWT tokens** (issued by a trusted authority)
2. Be registered as **consumers** in Kong
3. Have rate-limits enforced **per token/user**, not globally

## 🔐 What You'll Set Up

| Component     | Purpose                                                 |
| ------------- | ------------------------------------------------------- |
| JWT plugin    | Validates JWT tokens on requests                        |
| Consumer      | Represents each user/client in Kong                     |
| Public key    | Used by Kong to verify JWTs issued by trusted authority |
| Rate limiting | Applied per consumer to enforce user-specific quotas    |

## 🧱 Step 6.1: Create a Consumer in Kong

```
curl.exe -k -X POST "https://127.0.0.1:<admin-port>/consumers" --data "username=demo-user"
```

## 🔑 Step 6.2: Register a JWT Credential with Public Key

### Option A: If OpenSSL is not available on Windows

Use https://travistidwell.com/jsencrypt/demo/ to generate an RSA key pair in your browser:

1. Copy the **private key** and save it as `private.key`
2. Copy the **public key** and save it as `public.pem`

### Option B: If OpenSSL is installed (e.g., via Git Bash or WSL)

```
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.pem
```

### Upload the **public key** to Kong:

```
curl.exe -k -X POST "https://127.0.0.1:<admin-port>/consumers/demo-user/jwt" `
  --data "algorithm=RS256" `
  --data-urlencode "rsa_public_key=$(Get-Content .\public.pem -Raw)" `
  --data "key=demo-key"
```

> 🔐 Kong will now accept JWTs signed with your private key.

## 🔌 Step 6.3: Enable JWT Plugin on the Route

```
curl.exe -k -X POST "https://127.0.0.1:<admin-port>/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins" --data "name=jwt"
```

Check JWT setting:

```
curl.exe -k https://127.0.0.1:<admin-port>/consumers/demo-user/jwt
```



## 🧪 Step 6.4: Create and Sign a JWT for Testing

- ### 🧠 What is a JWT?

  A **JWT (JSON Web Token)** is a digitally signed string that encodes information (called “claims”) like:

  - who you are (`sub`)
  - who issued the token (`iss`)
  - when it expires (`exp`)

  ------

  ### ✅ JWT Format

  A JWT looks like this:

  ```
  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsImlzcyI6ImRlbW8ta2V5IiwiZXhwIjoxNzAwMDAwMDAwfQ.abc123signature
  ```

  It has 3 parts:

  1. **Header** (usually specifies `RS256`)
  2. **Payload** (your claims)
  3. **Signature** (signed using your `private.key`)

  ------

  ### 📄 What Kong needs in your JWT

  | Claim | Value                        | Why                                                          |
  | ----- | ---------------------------- | ------------------------------------------------------------ |
  | `iss` | `demo-key`                   | Must match the `key` value you gave Kong when registering the JWT credential |
  | `sub` | `demo-user`                  | Optional but useful — describes the user                     |
  | `exp` | Unix timestamp in the future | Prevents replay attacks                                      |

  

  ------

  ### ✅ Option A: Use https://jwt.io

  This is the easiest way:

  ### Steps:

  1. Go to https://jwt.io

  2. On the left:

     - **Header**:

       ```json
       {
         "alg": "RS256",
         "typ": "JWT"
       }
       ```

     - **Payload**:

       ```json
       {
         "iss": "demo-key",
         "sub": "demo-user",
         "exp": 1957468800
       }
       ```

     > You can generate a valid `exp` timestamp here

  3. Scroll down and paste your **private.key** into the “Private Key” field.

  4. Copy the encoded JWT from the top — this is what you’ll use in your requests.

  ------

  ### ✅ Option B: Use Python to Sign the Token

  If you prefer command-line/script:

  ```python
  import jwt
  import datetime
  
  private_key = open("private.key", "r").read()
  
  payload = {
      "iss": "demo-key",
      "sub": "demo-user",
      "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
  }
  
  token = jwt.encode(payload, private_key, algorithm="RS256")
  print(token)
  ```

  > Requires the `pyjwt` module:
  >  `pip install pyjwt`

  ------

  ### 🧪 Example Signed JWT Request

  Use the token via curl:

  ```
  curl.exe -H "Authorization: Bearer <your_jwt_token>" http://127.0.0.1:<proxy-port>/api/hello
  ```
  
  Use the token in Postman or curl:
  
  ```
  GET http://127.0.0.1:<proxy-port>/api/hello
  Authorization: Bearer <your-jwt-token>
  ```

  If the token is valid, you’ll get:

  ```json
  {"message": "Hello from the backend!"}
  ```
  
  If not:
  
  ```
  HTTP/1.1 401 Unauthorized
  ```

## 📬 Step 6.5: Make a JWT Authenticated Request

In Postman or `curl.exe`:

```
GET /api/hello
Host: 127.0.0.1:<proxy-port>
Authorization: Bearer <your-jwt-token>
```

You should get:

```
{"message": "Hello from the backend!"}
```

If the JWT is missing or invalid:

```
HTTP/1.1 401 Unauthorized
```

## 📊 Step 6.6: Apply Rate-Limiting per Consumer

```
curl.exe -k -X POST "https://127.0.0.1:<admin-port>/consumers/demo-user/plugins" --data "name=rate-limiting" --data "config.minute=3" --data "config.policy=local"
```

✅ Now each JWT-authenticated user is limited individually to 3 requests per minute.

## ✅ Step 7: Logging + Monitoring First, then Add OAuth2

------

## 🎯 Objective

In this step, we will **first establish API observability and control**, and then layer on **user authentication** using OAuth2 Proxy.

Specifically, we'll:

- ✅ Enable **request logging** with Kong using `http-log` plugin
- ✅ Enable **per-consumer rate limiting**
- ✅ Later, introduce **OAuth2 login with GitHub**
- ⚠️ Skip the JWT plugin (OAuth2 Proxy manages sessions via cookies)

------

## 7.1: Enable Request Logging with `http-log` Plugin

### 🧱 1. Deploy a mock logging service

```bash
kubectl run mock-logger --image=kennethreitz/httpbin --port=80
kubectl expose pod mock-logger --port=80 --target-port=80 --name=mock-logger
```

### 🧩 2. Enable Kong http-log plugin on a specific route

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<your-route-id>/plugins `
  --data name=http-log `
  --data config.http_endpoint=http://mock-logger.default.svc.cluster.local/post `
  --data config.method=POST `
  --data config.timeout=1000 `
  --data config.keepalive=1000
```

✅ You can now inspect logs from:

```bash
kubectl logs pod/<mock-logger-pod-name>
```

------

## 7.2: Add Rate Limiting

Optional but useful for demonstrating control at the consumer level:

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<route-id>/plugins `
  --data name=rate-limiting `
  --data config.minute=5 `
  --data config.policy=local
```

------

## 7.3: Register a Kong Consumer (Optional for Logging, Required for OAuth2)

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers `
  --data username=demo-user
```

------

## 7.4: Deploy OAuth2 Proxy (GitHub Login)

> This adds GitHub login and passes user info to the backend.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
  labels:
    app: oauth2-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: oauth2-proxy
  template:
    metadata:
      labels:
        app: oauth2-proxy
    spec:
      containers:
        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy:v7.4.0
          args:
            - --provider=github
            - --http-address=0.0.0.0:4180
            - --upstream=http://backend-api.default.svc.cluster.local
            - --scope=user:email
            - --email-domain=*
            - --client-id=Ov23li5oY0IBjJ9BPMah
            - --client-secret=3dc0182d49f0e665cf30d8ae3bacfb7133281d97
            - --redirect-url=http://localhost:4180/oauth2/callback
            - --cookie-secret=-sLi8SX'?M"{_Om`4|}k&d,tgG:[hy>p
            - --cookie-secure=false
            - --set-authorization-header=true
            - --show-debug-on-error=true
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy
spec:
  selector:
    app: oauth2-proxy
  ports:
    - protocol: TCP
      port: 80
      targetPort: 4180
```

Deploy this Oauth2-proxy and forward the port:

```bash
kubectl apply -f .\oauth2-proxy\oauth2-proxy.yaml
kubectl port-forward service/oauth2-proxy 4180:80
```

------

## 7.5: Test End-to-End Flow

### ✅ 1. Open browser:

```bash
http://localhost:4180/oauth2/start
```

### ✅ 2. Login via GitHub

### ✅ 3. Open Postman:

```
GET http://localhost:4180/api/hello
Cookie: _oauth2_proxy=<your-cookie-value>
```

### ✅ 4. Confirm in:

- `kubectl logs deployment/backend-api` → Flask receives request
- `kubectl logs deployment/mock-logger` → Kong logs request data