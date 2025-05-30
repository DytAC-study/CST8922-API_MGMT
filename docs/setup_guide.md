# ⚙️ Setup Guide: Kong + JWT + OAuth2 + Logging

---

## 1️⃣ Setup Kong in DB Mode

```bash
helm uninstall kong -n kong
helm repo add kong https://charts.konghq.com
helm repo update

helm install kong kong/kong -n kong --create-namespace   --set postgresql.enabled=true   --set env.database=postgres   --set env.pg_user=kong   --set env.pg_password=kongpass   --set admin.enabled=true   --set admin.type=NodePort   --set proxy.type=NodePort   --wait --timeout 5m
```

Find ports:

```bash
minikube service kong-kong-admin -n kong --url
minikube service kong-kong-proxy -n kong --url
```

---

## 2️⃣ Deploy Flask API

```bash
kubectl apply -f backend-api/deployment.yaml
```

Test locally:

```bash
kubectl port-forward service/backend-api 5000:5000
http://localhost:5000/
```

---

## 3️⃣ Register Service + Route in Kong

```bash
curl.exe -k -X POST https://127.0.0.1:<admin-port>/services   --data "name=backend-api"   --data "url=http://backend-api.default.svc.cluster.local"

curl.exe -k -X POST https://127.0.0.1:<admin-port>/services/backend-api/routes   --data "paths[]=/api/hello"   --data "strip_path=false"
```

---

## 4️⃣ Set Up JWT Authentication

### 4.1 Generate RSA Key Pair

Option A: Use browser: https://travistidwell.com/jsencrypt/demo/  
Option B: Use OpenSSL:

```bash
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.pem
```

### 4.2 Register Kong Consumer + Public Key

```bash
curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers   --data "username=demo-user"

curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers/demo-user/jwt   --data "algorithm=RS256"   --data "key=demo-key"   --data-urlencode "rsa_public_key=$(Get-Content .\public.pem -Raw)"
```

### 4.3 Enable JWT Plugin

```bash
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<route-id>/plugins   --data "name=jwt"
```

---

## 5️⃣ Test JWT Auth

1. Go to https://jwt.io  
2. Use:

```json
Header:
{
  "alg": "RS256",
  "typ": "JWT"
}
Payload:
{
  "iss": "demo-key",
  "sub": "demo-user",
  "exp": <some future Unix timestamp>
}
```

3. Paste your private key → copy the signed token

4. Use Postman:

```http
GET http://127.0.0.1:<proxy-port>/api/hello
Authorization: Bearer <your-token>
```

---

## 6️⃣ Add Logging + Rate Limiting

### 6.1 Logging (http-log)

```bash
kubectl run mock-logger --image=kennethreitz/httpbin --port=80
kubectl expose pod mock-logger --port=80 --target-port=80 --name=mock-logger

curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<route-id>/plugins   --data "name=http-log"   --data "config.http_endpoint=http://mock-logger.default.svc.cluster.local/post"   --data "config.method=POST"
```

### 6.2 Rate Limiting

```bash
curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers/demo-user/plugins   --data "name=rate-limiting"   --data "config.minute=3"
```

---

## 7️⃣ Add OAuth2 Proxy (GitHub Login)

Apply YAML:

```bash
kubectl apply -f oauth2-proxy/oauth2-proxy.yaml
kubectl port-forward service/oauth2-proxy 4180:80
```

Login:

```bash
http://localhost:4180/oauth2/start
```

Cookie:

- Find `_oauth2_proxy` in browser DevTools
- Paste into Postman as:

```http
GET http://localhost:4180/api/hello
Cookie: _oauth2_proxy=<value>
```

✅ You'll hit Flask and see headers like:

- `X-Forwarded-User`
- `X-Forwarded-Email`

> ⚠ OAuth2 Proxy does not expose JWTs — only cookies

---

## 🔚 Summary

| Feature         | Method             |
| --------------- | ------------------ |
| API Gateway     | Kong               |
| Initial Auth    | JWT (Bearer Token) |
| GitHub Auth     | OAuth2 → Cookie    |
| User Management | Kong Consumer      |
| Tracing/Logging | Kong `http-log`    |

