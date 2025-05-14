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
from flask import Flask
app = Flask(__name__)

@app.route("/api/hello")
def hello():
    return {"message": "Hello from the backend!"}

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
kubectl apply -f backend-api/deployment.yaml
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

Test it:

```
curl.exe -k https://127.0.0.1:54435/services
```

You may see something like:

```
{"data":[],"next":null}
```

because there's no registered service.

------

## 🧪 Step 4.3: Register Your Backend Service

Use this command in PowerShell:

```powershell
curl.exe -k -i -X POST https://127.0.0.1:54435/services `
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
curl.exe -k -X POST https://127.0.0.1:54435/services/backend-api/routes `
  --data "paths[]=/api/hello" `
  --data "strip_path=false"
```

Tell Kong not to strip the path. That way, Kong forwards `/api/hello` → `/api/hello` (instead of `/`

### Double check：

### ✅ 1. Service in Kong is defined like this:

```powershell
curl.exe -k https://127.0.0.1:54435/services
```

You should see:

```json
"url": "http://backend-api.default.svc.cluster.local"
```

------

### ✅ 2. Route is configured with `strip_path: false`

Check:

```bash
curl.exe -k https://127.0.0.1:54435/routes
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

- If rate limiting is active and you’ve hit the limit, you’ll see:

```
HTTP 429 Too Many Requests
```

------

### 🔍 3. Optional: View headers

In the **response headers**, you’ll see:

- `X-RateLimit-Limit: 5`
- `X-RateLimit-Remaining: 0`
- `Retry-After: 60`

These tell you that Kong’s **rate-limiting plugin** is working.

------

### 💡 Extra Tips:

- You don’t need to add any headers or body — just a `GET` request is enough.
- If you later add **JWT auth**, you’ll need to add a **Bearer Token** under the **Authorization** tab.



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
curl.exe -k https://127.0.0.1:54435/routes
```

Look for the `id` of the route with:

```
jsonCopyEdit"paths": ["/api/hello"],
"strip_path": false
```

Let's assume it's:

```
f372164a-70d3-40a6-931e-dc59284a3988
```

------

### ✅ Step 2: Add the rate-limiting plugin

```powershell
curl.exe -k -X POST https://127.0.0.1:54435/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins `
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
curl.exe -k -X POST "https://127.0.0.1:54435/consumers" --data "username=demo-user"
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
curl.exe -k -X POST "https://127.0.0.1:54435/consumers/demo-user/jwt" `
  --data "algorithm=RS256" `
  --data-urlencode "rsa_public_key=$(Get-Content .\public.pem -Raw)" `
  --data "key=demo-key"
```

> 🔐 Kong will now accept JWTs signed with your private key.

## 🔌 Step 6.3: Enable JWT Plugin on the Route

```
curl.exe -k -X POST "https://127.0.0.1:54435/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins" --data "name=jwt"
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
curl.exe -k -X POST "https://127.0.0.1:54435/consumers/demo-user/plugins" --data "name=rate-limiting" --data "config.minute=3" --data "config.policy=local"
```

✅ Now each JWT-authenticated user is limited individually to 3 requests per minute.



# ✅ Step 7 (Rewritten): OAuth2 Proxy + JWT Auth + Per-Consumer Rate Limit + Logging (DB Mode)

------

## 🎯 Objective

Demonstrate how Kong can:

- Accept JWTs signed by a trusted OAuth2 Proxy
- Enforce route access via JWT
- Apply per-user rate limiting
- Log authenticated traffic for auditing and debugging

------

## 🔐 Step 7.1: Add OAuth2 Proxy to Automate JWT Flow

## 🎯 Goal

Allow users to log in via GitHub and receive a **JWT automatically** — no manual JWT copy-pasting required. This makes your Kong-secured route usable in a browser or with live OAuth2-based identity.

------

## 🔧 Deployment Steps

### 🛠 1. Create a GitHub OAuth App

In your GitHub account:

1. Go to **Settings > Developer Settings > OAuth Apps**
2. Register a new app:
   - **Homepage URL**: `http://localhost:4180`
   - **Authorization Callback URL**: `http://localhost:4180/oauth2/callback`
3. Note the:
   - `Client ID`
   - `Client Secret`

------

### 📦 2. Generate a JWT RSA key pair

If you haven’t done so yet:

```
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.pem
```

Use `public.pem` with Kong (`key=demo-key`)
 Mount `private.key` inside the OAuth2 Proxy pod.

------

### 🧱 3. Create a Kubernetes `Secret` for the private key

```
kubectl create secret generic jwt-private-key \
  --from-file=private.key=./private.key
```

------

### 📄 4. Deploy `oauth2-proxy`

Here’s a minimal `oauth2-proxy.yaml`:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
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
        - --cookie-secret=replace-this-32B-base64
        - --client-id=REPLACE_WITH_YOURS
        - --client-secret=REPLACE_WITH_YOURS
        - --redirect-url=http://localhost:4180/oauth2/callback
        - --email-domain=*
        - --set-authorization-header=true
        - --jwt-signing-key=/etc/secrets/private.key
        volumeMounts:
        - name: jwt-key
          mountPath: /etc/secrets
          readOnly: true
      volumes:
      - name: jwt-key
        secret:
          secretName: jwt-private-key
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy
spec:
  ports:
  - port: 80
    targetPort: 4180
  selector:
    app: oauth2-proxy
```

Apply it:

```
kubectl apply -f oauth2-proxy.yaml
```

------

### 🌐 5. Access the login flow

```
kubectl port-forward svc/oauth2-proxy 4180:80
```

Open your browser:

```
http://localhost:4180/oauth2/start
```

✅ You’ll be redirected to GitHub to log in
 ✅ On success, OAuth2 Proxy will inject a JWT into:

- `Authorization: Bearer <JWT>` header (used by Kong)
- or a cookie (optional)

------

### ✅ 6. Test It with Kong

Use Postman or browser to call:

```
javascriptCopyEditGET http://127.0.0.1:<kong-proxy-port>/api/hello
Authorization: Bearer <OAuth2 Proxy JWT>
```

✅ You should pass Kong’s JWT check and see the Flask response
 ✅ If rate limiting is set for your `demo-user`, that will also apply

## 👤 Step 7.2: Ensure Kong Consumer Exists

If not already created:

```powershell
curl.exe -k -X POST https://127.0.0.1:54435/consumers --data "username=demo-user"
```

------

## 🔑 Step 7.3: Register Public Key for JWT Verification

If not already done:

```
powershellCopyEdit$pubkey = Get-Content .\public.pem -Raw
curl.exe -k -X POST "https://127.0.0.1:54435/consumers/demo-user/jwt" `
  --data "algorithm=RS256" `
  --data-urlencode "rsa_public_key=$pubkey" `
  --data "key=demo-key"
```

------

## 🔌 Step 7.4: Enable JWT Plugin on the `/api/hello` Route

```
powershellCopyEditcurl.exe -k -X POST https://127.0.0.1:54435/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins `
  --data "name=jwt"
```

✅ This tells Kong to expect and validate JWTs on that route.

------

## 🔒 Step 7.5: Enable Rate Limiting for the JWT Consumer

```
powershellCopyEditcurl.exe -k -X POST https://127.0.0.1:54435/consumers/demo-user/plugins `
  --data "name=rate-limiting" `
  --data "config.minute=3" `
  --data "config.policy=local"
```

🎯 Limits this specific user to 3 requests/min, regardless of what others do.

------

## 📦 Step 7.6: Enable HTTP Logging for JWT-Protected Route

```
powershellCopyEditcurl.exe -k -X POST "https://127.0.0.1:54435/routes/f372164a-70d3-40a6-931e-dc59284a3988/plugins" `
  --data "name=http-log" `
  --data "config.http_endpoint=http://mock-logger.default.svc.cluster.local/post" `
  --data "config.method=POST"
```

🔎 Now Kong will log JWT-authenticated traffic to the mock endpoint for observability.

------

## 🧪 Step 7.7: Test the End-to-End Flow

1. Visit OAuth2 Proxy’s `/oauth2/start`

2. Log in and copy your `Authorization: Bearer <JWT>` header

3. Use Postman or curl to call:

   ```
   perlCopyEditGET http://<kong-proxy-url>/api/hello
   Authorization: Bearer <JWT>
   ```

4. Check that:

   - ✅ Request succeeds
   - 🔄 Logging is triggered
   - ❌ Request #4 (within a minute) is rate-limited (429)





------

# 🎤 Demo Script: Scalable API Management (Kong + JWT + Rate Limiting)

> ⏱️ Target Duration: 1 hour (with smooth handoffs between teammates)

------

## 🔰 1. Demo Introduction (2–3 mins)

**Presenter A:**

> "Hi everyone, today we’ll demonstrate how to secure, monitor, and scale APIs using **Kong Gateway** with features like **rate limiting** and **JWT-based authentication**.
>  We'll walk you through a real-world Kubernetes setup using Kong OSS, a Flask API, OAuth2 Proxy, and GitHub as our identity provider."

------

## 🧱 2. Backend API Deployment (3–5 mins)

**Presenter B (shares screen):**

> "Let’s start with our backend — a simple Flask API deployed to Kubernetes."

### Actions:

- Show `app.py`: returns “Hello from backend”

- Show `deployment.yaml`

- Run:

  ```bash
  kubectl apply -f backend-api/deployment.yaml
  kubectl get pods
  ```

> "This deploys our API and exposes it as a ClusterIP service inside Kubernetes."

------

## 🌐 3. Deploy Kong Gateway (3–5 mins)

**Presenter C:**

> "Now we deploy Kong OSS using Helm."

### Actions:

- Run:

  ```bash
  helm install kong kong/kong -n kong --create-namespace \
    --set ingressController.installCRDs=false \
    --set proxy.type=NodePort \
    --set admin.type=NodePort
  ```

- Show:

  ```bash
  minikube service -n kong kong-kong-proxy --url
  ```

------

## 🔗 4. Register API Service and Route in Kong (5–7 mins)

**Presenter C:**

> "Now we’ll use Kong’s Admin API to register our backend service and route traffic to it."

### Actions:

```bash
curl -X POST $KONG_ADMIN_URL/services \
  --data name=backend-api \
  --data url=http://backend-api.default.svc.cluster.local

curl -X POST $KONG_ADMIN_URL/services/backend-api/routes \
  --data paths[]=/api/hello
```

> "Let’s test that with Postman."

- Show response from `http://<kong-proxy-url>/api/hello`

------

## 🚫 5. Global Rate Limiting (5 mins)

**Presenter D:**

> "To prevent abuse, we’ll now apply a **global rate limit** of 5 requests/minute."

### Actions:

```bash
curl -X POST $KONG_ADMIN_URL/routes/<route-id>/plugins \
  --data name=rate-limiting \
  --data config.minute=5 \
  --data config.policy=local
```

- Demo sending 5+ requests in Postman
- Show 429 Too Many Requests

------

## 🔐 6. OAuth2 Proxy Authentication (10 mins)

**Presenter A:**

> "Now let’s secure our API using **OAuth2 Proxy**, which authenticates via GitHub."

### Actions:

- Explain GitHub OAuth setup (show dummy values)

- Apply `oauth2-proxy/deployment.yaml`

- Run:

  ```bash
  minikube service oauth2-proxy --url
  ```

- Visit `/oauth2/start`, log in via GitHub

> "After logging in, we receive a JWT that can be passed to Kong."

------

## 🔑 7. JWT Plugin in Kong (8–10 mins)

**Presenter B:**

> "We’ll now configure Kong to validate that JWT and allow access only if it's valid."

### Actions:

- Create consumer:

  ```bash
  curl -X POST $KONG_ADMIN_URL/consumers \
    --data username=demo-user
  ```

- Upload public key:

  ```bash
  curl -X POST $KONG_ADMIN_URL/consumers/demo-user/jwt \
    --data algorithm=RS256 \
    --data rsa_public_key="..." \
    --data key=demo-key
  ```

- Enable JWT plugin:

  ```bash
  curl -X POST $KONG_ADMIN_URL/routes/<route-id>/plugins \
    --data name=jwt
  ```

> "Now, only requests with valid JWTs will go through."

- Test: Postman → JWT → `/api/hello`

------

## 📊 8. Per-User Rate Limiting (5–6 mins)

**Presenter D:**

> "We can now apply **per-consumer limits**, like 3 requests/min per logged-in user."

### Actions:

```bash
curl -X POST $KONG_ADMIN_URL/consumers/demo-user/plugins \
  --data name=rate-limiting \
  --data config.minute=3 \
  --data config.policy=local
```

- Show difference: user A vs. unauthenticated user
- Simulate two users (or show logs with different tokens)

------

## 📦 9. Wrap-Up & Real-World Applications (2 mins)

**All Together:**

> "This setup allows you to:
>
> - Protect APIs using standard auth (OAuth2 / JWT)
> - Control traffic usage fairly
> - Scale safely without overloading your services"

> "It’s ideal for multi-tenant platforms, API products, and cloud-native apps."

------

## ❓ 10. Q&A and Discussion (15 mins)

- Prepare a few fallback questions if the class is silent:
  - “How would this change in a production environment?”
  - “Why use Kong over an API key system?”
  - “What if your backend supports gRPC instead of HTTP?”



# ✅ GitHub Repo Structure (Recommended)

Here's a structure that matches your presentation flow and supports hands-on demos:

```bash
scalable-api-management-demo/
├── backend-api/
│   ├── app.py
│   ├── Dockerfile
│   └── deployment.yaml
├── kong/
│   ├── kong-service-setup.md         # curl commands for Admin API
│   └── screenshots/                  # (optional) Postman/Kong UIs
├── oauth2-proxy/
│   ├── deployment.yaml
│   ├── config-reference.md           # (optional) explain args/env
├── ingress/                          # (optional) if using KongIngress
├── secrets/                          # .gitignore — describe what to generate (e.g., private.key)
├── setup-guide.md                    # 👈 MASTER INSTRUCTION FILE
├── README.md                         # overview of repo and tools
└── slides/
    ├── presentation.pptx
    └── demo-script.pdf
```

------

# 📘 `README.md` Template (overview)

```markdown
# Scalable API Management Demo

This project demonstrates scalable API management using Kong OSS, OAuth2 Proxy, JWT Auth, and Kubernetes.

## Key Features
- Kong API Gateway with declarative and Admin API setups
- Global and per-user rate limiting
- OAuth2 login via GitHub and JWT validation
- Backend Flask API served in Kubernetes

## Tools
- Kong Gateway OSS
- OAuth2 Proxy
- Postman
- Kubernetes (Minikube)
- GitHub OAuth

## Quick Start
See [setup-guide.md](./setup-guide.md) for full deployment instructions.
```