# Scalable API Management with Rate Limiting and JWT Auth (Kong Gateway on Minikube)

## Introduction and Overview

In modern microservice architectures, APIs need a **single entry point** to handle cross-cutting concerns like authentication, authorization, and traffic control. An **API Gateway** fulfills this role by sitting between clients and backend services (acting as a reverse proxy) and enforcing centralized policies. For our project, we focus on deploying **Kong API Gateway** (an open-source solution) in a local Kubernetes (Minikube) environment, protecting a simple Flask API with **JWT-based authentication** and **rate limiting**, and monitoring requests via tools like Postman. The presentation demonstrates how an API gateway can **secure and scale** API access – even in a local cluster – through configurable plugins and integration with an OAuth2 identity provider.

**Key Features to Implement:**

- **Authentication & Authorization:** Using JWT tokens (and an OAuth2 Proxy for login flow) to ensure only authenticated users can access the API.
- **Rate Limiting:** Enforcing call quotas (e.g. 5 requests/minute) to prevent abuse[apipark.com](https://apipark.com/techblog/en/understanding-kong-api-gateway-a-comprehensive-guide-for-beginners-2/#:~:text=* Use Token,and respond to them promptly) and illustrate protection against DDoS or overload.
- **API Gateway Monitoring:** Logging and tracing requests through Kong (and a mock logging service) and using Postman to verify headers and responses.
- **Scalability & Modularity:** Using Kubernetes to deploy all components (gateway, auth proxy, backend) and demonstrating how policies can be adjusted without changing the backend.

By the end, we will have a **local API gateway** on Minikube that fronts a backend API, requires valid JWT tokens (or OAuth2 login), limits request rates, and logs traffic – providing a holistic view of API management in practice.

## Understanding API Gateways and Plugins

![img](blob:https://chatgpt.com/99f33b7d-258c-4682-86eb-39b6eceb9718) *Figure: A conceptual view of an API Gateway as a central entry point. The gateway handles common concerns (security, transformations, logging, monitoring) for multiple downstream microservices[konghq.com](https://konghq.com/blog/learning-center/what-is-an-api-gateway#:~:text=As organizations adopt microservices architecture%2C,can help address these issues)[descope.com](https://www.descope.com/blog/post/kong-gateway-authentication#:~:text=The Kong Gateway is a,seamless API integration and high).*

**What is an API Gateway?** In essence, an API gateway is **middleware** that routes client requests to appropriate services and enforces policies. It acts as **a single entry point** for clients to access one or more microservices. Instead of clients calling services directly, all calls go through the gateway, which can handle **authentication**, **rate limiting**, **data transformation**, caching, load balancing, and more. This indirection simplifies client interactions (the client only talks to the gateway) and centralizes logic like security. Kong Gateway, for example, allows you to manage and secure API traffic with plugins for auth, rate-limit, logging, etc. This architecture improves scalability and security by offloading these concerns from individual services to the gateway layer.

**Why use plugins?** API Gateways like Kong or Tyk are designed to be extensible via **plugins**. Plugins are modules that execute on each request/response, implementing features such as JWT validation, OAuth2 flows, rate limiting, logging, etc. These can often be toggled or configured per service or route. For instance, Kong’s plugin system allows enabling JWT auth on certain routes, or a global rate-limit plugin for an API, without touching the service’s code. This modular approach means we can add or adjust policies on the fly (via configuration) and achieve **consistent enforcement** across all services.

**JWT vs OAuth2 (OAuth2 Proxy):** We will demonstrate two auth strategies: **JWT authentication** (where a token is issued and verified by the gateway) and **OAuth2 login flows** via an external provider (using an OAuth2 Proxy). JWT (JSON Web Token) is a stateless token format that contains claims (user identity, expiration, etc.) and is signed by a trusted authority. The gateway can verify this signature to authenticate users without querying a database on each request. OAuth2, on the other hand, involves redirecting users to an identity provider (e.g. GitHub or Google) to log in; after login, a token or session cookie is provided, which the gateway (or a proxy component) uses to allow access. In our setup, **OAuth2 Proxy** is a separate component that handles that redirection and token issuance (using GitHub OAuth in our case), then passes an authenticated request to the backend. We will see how Kong can integrate with such a proxy by treating it as an upstream service for authenticated routes.

**Rate Limiting:** Rate limiting is crucial for **scalability and reliability**. It ensures no single client can overwhelm the API by capping the number of requests allowed in a time window. Gateways often implement this via plugins (Kong’s `rate-limiting` plugin) which can track request counts per consumer or globally, and reject requests with `HTTP 429 Too Many Requests` once limits are exceeded. This protects the backend from abuse and smooths out traffic spikes.

**Kong vs Tyk:** Both Kong and Tyk are popular open-source API gateways with similar capabilities (auth, rate limiting, transformation, monitoring). In our demo we use **Kong OSS** for hands-on configuration, but the concepts (deploying a gateway in front of services, applying plugins) would be analogous in Tyk. Kong provides an Admin API and declarative config; Tyk has a dashboard and config files – either could be used for a local demo. (If time permits, we could note differences or why Kong was chosen – e.g., large community and plugin ecosystem.)

## Technology Stack and Tools

Our demo stack consists of the following components (all running locally on Minikube):

- **Kong Gateway (Open-Source edition):** API gateway enforcing auth and rate limiting policies. Deployed via the official Helm chart.
- **OAuth2 Proxy:** An open-source OAuth2 proxy (configured for GitHub OAuth) that runs behind Kong to handle user login and issue JWT cookies. It adds an authentication layer by integrating with an external Identity Provider (IdP).
- **Backend API:** A simple Flask application (Python) providing a demo endpoint (`/api/hello`). This simulates our protected microservice. It’s containerized with Docker.
- **Kubernetes (Minikube):** Used to orchestrate the above components. Minikube provides a local K8s cluster; we use it to deploy the backend API, Kong, and OAuth2 Proxy as pods/services.
- **Postman & cURL:** Tools for testing the API from a client perspective. Postman will be used in the demo to simulate requests, present headers, and demonstrate the effect of auth and rate limits. cURL (or PowerShell `curl.exe`) is used in setup steps (especially to configure Kong via its Admin API).
- **Helm & kubectl:** Helm is used to install Kong on K8s easily, and `kubectl` to manage resources (deployments, services, etc.).

Additionally, for monitoring/logging demonstration, we use **httpbin** (via a `mock-logger` service) to collect request logs from Kong’s logging plugin, and the **Kong Admin API** for any runtime configuration changes.

With this stack, we’ll walk through deploying each piece and verifying that the end-to-end system meets our goals: the user must authenticate (JWT or OAuth2) and is subject to rate limits, and the gateway will log and proxy the request to the backend service.

## Architecture Diagram and Flow

![img](blob:https://chatgpt.com/74b137e3-7a96-4670-8948-b1a8f72cf54f) *Figure: High-level request flow in our demo architecture. Kong Gateway sits in front of the OAuth2 Proxy and Flask API. If a user is not authenticated, the OAuth2 Proxy triggers a login (dashed lines show the redirect flow to an external IdP like GitHub). Once authenticated (user returns with an auth code/cookie), Kong proxies the API call to the OAuth2 Proxy, which forwards it to the backend service. Kong’s plugins (e.g., JWT auth, rate limiting) can be applied on the path before the request reaches the backend.*

The architecture can be thought of in layers:

- **Client (User/Postman):** Initiates requests to the API endpoint (e.g., `GET /api/hello`). In a browser scenario, if not logged in, the user would be redirected to an OAuth2 provider (GitHub) to authenticate.
- **Kong API Gateway:** The first point of contact for API requests. Kong will check if the request matches a defined route and then apply configured plugins. For example:
  - **JWT Auth Plugin:** If enabled, Kong will require a valid JWT in the `Authorization` header and verify it (using a public key for the issuer). If the token is missing or invalid, Kong immediately responds with `401 Unauthorized`.
  - **Rate Limiting Plugin:** Kong will count the request (per route or per consumer) and potentially throttle if the limit is exceeded (returning `429 Too Many Requests`).
  - If the request passes all plugin checks, Kong routes it to the appropriate upstream service.
- **OAuth2 Proxy (Upstream Service 1):** This acts as an authentication layer in the OAuth2 flow. Kong can be configured to route certain requests (e.g., any request to the protected API path) to the OAuth2 Proxy first. The proxy checks for a valid session cookie:
  - If the user is not authenticated, the proxy **redirects** the user to the OAuth2 provider’s consent page (GitHub OAuth). After the user logs in and approves, the provider redirects back to the proxy with an auth code, and the proxy then obtains an ID token or sets a session cookie. (This redirect loop is shown with dashed arrows in the figure.)
  - Once the user has a valid session, the OAuth2 Proxy forwards the request to the actual backend service, adding **headers** like `X-Forwarded-User` and `X-Forwarded-Email` to convey the user’s identity.
- **Flask API (Upstream Service 2):** The final destination that handles the request (if authentication and rate checks passed). In our demo, this is a simple Flask app that responds with a JSON greeting and echoes back the `X-Forwarded-User/Email` it received in the request headers. It is oblivious to the gateway’s presence – it just sees incoming requests (the gateway and proxy ensure those requests are from authenticated, allowed users).

**Architecture summary:** The user’s request goes to Kong → Kong enforces auth (JWT or via OAuth2 Proxy) and rate limiting → the request is passed to Flask API → response goes back to the client. This setup emulates a **zero-trust environment** where the gateway strictly checks credentials and usage, giving the backend confidence that incoming traffic is safe and within expected volumes.

## Step 1: Building the Backend API (Flask)

The first component is the **backend API**, a simple Flask application that we’ll protect behind the gateway. This API has a couple of endpoints:

- `GET /api/hello` – returns a JSON message, e.g. `{ "message": "Hello from backend API" }`. It also includes user info from headers if present (e.g. it will read `X-Forwarded-User` and `X-Forwarded-Email` headers set by the auth proxy and include them in the response).
- `GET /` (root) – optional health-check or OAuth2 Proxy check endpoint, which can confirm the OAuth2 Proxy is working by echoing the forwarded user info as well.

For example, the Flask code for `/api/hello` might look like this (simplified):

```
pythonCopyEdit@app.route("/api/hello")
def hello():
    return jsonify({
        "message": "Hello from backend API",
        "user": request.headers.get("X-Forwarded-User"),
        "email": request.headers.get("X-Forwarded-Email")
    })
```

This ensures that if the request passes through the OAuth2 Proxy with an authenticated session, the backend can see who the user is. (If the headers are missing, it likely means the request was unauthenticated.) The Flask app listens on port 5000.

After writing the Flask app (`app.py`), we create a **Dockerfile** to containerize it. The Dockerfile is straightforward:

```
dockerfileCopyEditFROM python:3.9
WORKDIR /app
COPY app.py .
RUN pip install flask
EXPOSE 5000
CMD ["python", "app.py"]
```

We then build the Docker image and push it to Docker Hub (so Minikube can pull it). Steps:

1. **Build the image:** `docker build -t <your-dockerhub-username>/backend-api:latest .` (run in the `backend/` directory containing the Dockerfile).
2. **Test locally (optional):** You can run the container with `docker run -p 5000:5000 ...` to verify it serves the `/api/hello` endpoint.
3. **Push to Docker Hub:** `docker push <username>/backend-api:latest` and ensure the image is accessible (you should see it in your Docker Hub repository).

Once the image is available, we move to deploying it on Kubernetes.

## Step 2: Deploying the Backend API on Minikube

With the container ready, we deploy the Flask API in Minikube using a Kubernetes **Deployment** and **Service**. The Deployment will run one replica of our backend API pod, and the Service will expose it internally so that other services (like Kong or OAuth2 Proxy) can reach it.

Key parts of the Kubernetes manifest (YAML):

- **Deployment:**
  - Uses the Docker image we pushed (`your-dockerhub-username/backend-api:latest`).
  - Container listens on port 5000.
  - We can start with 1 replica (this can be scaled later to test load balancing if desired).
- **Service:**
  - Exposes port 80 internally and forwards to the pod’s port 5000.
  - Labeled so that Kong or other cluster components can discover it by name (`backend-api.default.svc.cluster.local` will resolve to this service).

Apply the manifest using `kubectl apply -f backend-api/deployment.yaml`. After deployment, verify the pod is running: `kubectl get pods` should show the backend-api pod in `Running` state.

To test the backend in the cluster, we have a few options. Since it’s not (and need not be) exposed externally right now, one way is to use `kubectl port-forward` or temporarily expose it via NodePort:

- **Port-forward method:** `kubectl port-forward svc/backend-api 5000:80` – then on your localhost you can call `http://localhost:5000/api/hello`. It should return `{"message": "Hello from backend API", ...}`. (At this stage, `user` and `email` will likely be `null` because we aren’t sending those headers yet.)
- **Minikube service method:** Alternatively, you could use `minikube service backend-api --url` to get a URL for the service, but since this is a ClusterIP service by default (internal), you might first need to change it to NodePort. In practice, we will not directly expose the backend externally – the gateway will be the entry point – so direct testing can be limited to confirming the pod works.

✅ **Verification:** Once you see the **Hello** message from the backend API via one of these methods, you know the Flask service is up and running inside Minikube. We’re ready to introduce the gateway in front of it.

*(Note: In the final architecture, the backend’s \*only\* exposure will be through Kong, which will call it via the internal ClusterIP service. The backend itself won’t be reachable from outside the cluster – a principle of secure design.)*

## Step 3: Installing Kong API Gateway on Kubernetes

Now we deploy the **Kong API Gateway** in the cluster. We’ll use Helm for a quick setup. Kong’s Helm chart allows installing either DB-less mode or with a database (PostgreSQL). For our needs, we plan to dynamically configure routes and plugins via the Admin API, which works best in database-backed mode (so that configs can be added on the fly). We will install Kong along with a PostgreSQL sub-chart.

**Helm install:** Use the official chart repository. For example:

```
bashCopyEdithelm repo add kong https://charts.konghq.com
helm repo update
```

Then install Kong with a PostgreSQL database and enable the Admin and Proxy on NodePorts (so we can reach them from our host machine):

```
bashCopyEdithelm install kong kong/kong --create-namespace -n kong \
  --set postgresql.enabled=true \
  --set postgresql.auth.username=kong \
  --set postgresql.auth.password=kongpass \
  --set postgresql.auth.database=kong \
  --set env.database=postgres \
  --set env.pg_user=kong,env.pg_password=kongpass,env.pg_database=kong \
  --set admin.enabled=true --set admin.type=NodePort \
  --set proxy.type=NodePort \
  --set ingressController.enabled=false \
  --wait --timeout 5m
```

Let’s break down some of these settings:

- We enable the **PostgreSQL** database (with a simple username/password) and tell Kong to use it (`env.database=postgres` etc.). This puts Kong in traditional (database-backed) mode rather than the default DB-less.
- We enable the **Admin API** and set it to NodePort. The Admin API is Kong’s management API (by default it’s on port 8001 inside the cluster). Exposing it via NodePort allows us to hit it from the host (kubectl or curl) for configuration. We’ll secure access simply by keeping it local (and note: in production you’d lock this down).
- The **Proxy** (data plane) is also set to NodePort (Kong’s proxy listens on 8000 by default for HTTP). This will be the port that clients (Postman, etc.) use to hit the gateway.
- We disable Kong’s ingress controller component (`ingressController.enabled=false`) since we will configure Kong directly via API/Helm, not through Kubernetes Ingress resources in this demo.

Helm will deploy Kong and the database. The `--wait --timeout 5m` ensures the installation only completes when Kong’s pods are up and migrations have run. After a successful install, you should have (in namespace `kong`):

- A Kong pod (which includes the proxy and admin API).
- A Postgres pod for Kong.

Check with `kubectl get pods -n kong` and ensure the Kong pod status is Running.

Next, find the NodePort addresses for Kong’s Proxy and Admin endpoints. We can use Minikube shortcuts:

```
bashCopyEditminikube service kong-kong-proxy -n kong --url
minikube service kong-kong-admin -n kong --url
```

These commands output URLs like `http://127.0.0.1:31234` (for example). Suppose:

- Kong Admin API is at **http://127.0.0.1:32771** (random NodePort assigned)
- Kong Proxy is at **http://127.0.0.1:31234**

(Note: The Admin API might actually be on HTTPS with Kong’s default cert. If so, we’ll use `https://127.0.0.1:<admin-port>` with `-k` in curl to ignore self-signed cert issues.)

**Test Kong Admin connectivity:** Run a quick test:

```bash
curl.exe -k https://127.0.0.1:<admin-port>/services
```

If Kong is fresh, the response should be something like `{"data":[],"next":null}`, meaning no services are configured yet (an empty list). This is expected – we haven’t set up any upstream services in Kong.

At this point, Kong is running and ready to be configured. The next steps involve telling Kong about our backend API and setting up the necessary routes and plugins.

*(If you previously installed Kong in DB-less mode or need to reconfigure, you can uninstall with `helm uninstall kong -n kong` and then reinstall with the above settings. In our case, we directly installed in DB mode.)*

## Step 4: Configuring Kong Service and Route for the API

With Kong running, we use the **Admin API** to register our Flask service and the route(s) we want to expose. In Kong’s terminology:

- A **Service** object in Kong represents an upstream API (our Flask app) – basically the connection info for Kong to reach it.
- A **Route** object ties a client-facing request pattern (like an URL path) to that Service. The route tells Kong “if a request comes in for `/api/hello`, send it to the backend service”.

We will create a service and route for the `/api/hello` endpoint.

**1. Register the Backend Service in Kong:** Use Kong’s Admin API (`/services` endpoint):

```powershell
curl.exe -k -i -X POST https://127.0.0.1:<admin-port>/services `
  --data "name=backend-api" `
  --data "url=http://backend-api.default.svc.cluster.local"
```

Here we are naming the service `"backend-api"` and providing the URL of our Flask service inside the cluster. `backend-api.default.svc.cluster.local` is the Kubernetes DNS name for the service we deployed in Step 2. (Port 80 is implied by default in the URL; Kong will use that.)

If successful, Kong returns a `201 Created` and a JSON object representing the service (with an `id`, timestamps, etc.). Now Kong knows how to connect to our backend API.

**2. Create a Route for `/api/hello`:** Now we associate a route with that service:

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/services/backend-api/routes `
  --data "paths[]=/api/hello" `
  --data "strip_path=false"
```

This call says: for the service `backend-api`, create a route that matches requests with path `/api/hello`. We set `strip_path=false` so that Kong does **not** remove the path prefix when proxying (meaning Kong will forward the request to `http://backend-api.default.svc.cluster.local/api/hello` exactly, not strip it to `/`). This is important because our Flask app expects the `/api/hello` path.

*(We could also define an additional route for just `/` or other paths if needed. In our case, `/api/hello` is the main one of interest. The command above specifically uses the Admin API with service name; alternatively, one can use the service ID.)*

To verify, we can query Kong’s Admin API:

- `curl -k https://127.0.0.1:<admin-port>/services` should now list the `backend-api` service.
- `curl -k https://127.0.0.1:<admin-port>/routes` should list the route and show `"paths": ["/api/hello"]` and `"strip_path": false`file-uqmlnxgfnza9ad85zgi6b9.

**3. Test the Proxy without Plugins:** Now do a direct test of the entire chain: Call the Flask API *through Kong*. Using the Kong Proxy URL we got from Minikube:

```powershell
curl.exe http://127.0.0.1:<proxy-port>/api/hello
```

If everything is configured correctly, Kong will route this to the Flask service, and you should get a response from Flask, e.g.:

```json
{"message": "Hello from backend API", "user": null, "email": null}
```

At this point, the gateway is simply forwarding the request (no auth required yet, no rate limiting). This confirms Kong knows about the service and route. The response shows the backend works via the gateway. (The `user: null` is expected since we have not gone through OAuth2 login or provided any JWT – it’s an open call.)

In Postman, you can achieve the same by making a GET request to `http://127.0.0.1:<proxy-port>/api/hello`. You should see the JSON response from the backend. We haven’t configured any credentials or limits yet, so any call goes through.

Now that the baseline proxying is verified, we proceed to **secure and enhance** the API with Kong’s plugins.

## Step 5: Applying Rate Limiting (Protecting the API from Overuse)

One of the easiest policies to implement on Kong is the **Rate Limiting plugin**. We will first set a simple **global limit** on the `/api/hello` route – for example, 5 requests per minute across all clients. This simulates protecting the API from being spammed by anyone.

**Why Rate Limit:** As mentioned, it prevents abuse and ensures fair use of the API. Even in a demo, it’s useful to see how Kong can throttle calls. We’ll later refine it to per-user limits once auth is in place.

**1. Enable the rate-limiting plugin on the route:** We can do this via Admin API. First, we need the identifier of the route. You can get it by `GET /routes` – find the JSON for the route we created (it will have an `id` field, a UUID). Alternatively, since we know only one route exists for that service, we might retrieve it directly. For clarity, let’s assume we got a route ID like `f372164a-...` (we’ll use a placeholder).

Use the Admin API to add the plugin:

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<ROUTE_ID>/plugins `
  --data "name=rate-limiting" `
  --data "config.minute=5" `
  --data "config.policy=local"
```

This attaches the **Rate Limiting** plugin to that specific route. The config we provided means: allow 5 requests per minute. The `policy=local` means Kong will use in-memory counters (per Kong node). Since our demo likely has one Kong pod, this is fine. (For a distributed scenario, Kong could use a Redis or cluster policy to sync counters, but that’s beyond scope here.)

Kong should return a 201 Created for the plugin. Now any calls to `/api/hello` will go through the rate limiting logic.

**2. Test the rate limit:** Use Postman or a loop with curl:

- Make 5 quick requests to `GET /api/hello` through Kong. The first 5 should succeed (status 200).
- On the **6th request within the same minute**, expect `HTTP 429 Too Many Requests`. Kong will stop forwarding to the backend and immediately return 429 once the limit is exceededfile-uqmlnxgfnza9ad85zgi6b9.
- In Postman, you can send multiple requests manually or use a quick script. If using cURL in a loop, just run it 6 times.

Check the response headers on the 429 response. Kong by default includes helpful headers like:
 `X-RateLimit-Limit: 5` (the limit),
 `X-RateLimit-Remaining: 0` (remaining calls in the window),
 `Retry-After: 60` (how many seconds to wait until the quota resets)file-uqmlnxgfnza9ad85zgi6b9.

These headers confirm the plugin is active. In Postman, after receiving 429, you can inspect the **Headers** tab to see those values. They essentially tell the client “you’ve hit the limit, try again after 60 seconds.”

If you wait a minute (the counter resets after the window), you can call again and it should succeed.

**Rate Limiting verified:** We’ve now demonstrated Kong protecting the API by rate limiting all traffic. This is a **global limit** (it doesn’t matter if the calls are from the same user or not – it’s counting total requests to that route). Next, we’ll introduce authentication so that we can enforce **per-user** limits and ensure only authorized calls go through.

*(Note: The plugin was applied to the route, so if we had other routes or if we only wanted to limit specific consumers, we could attach the plugin in other ways. Kong’s flexibility allows rate limiting at Service level or per Consumer. We’ll see per-consumer usage after adding JWT.)*

## Step 6: Enforcing JWT Authentication for API Access

With rate limiting in place, the next layer is **authentication**. We will require clients to present a valid **JWT (JSON Web Token)** to access `/api/hello`. Kong provides a JWT authentication plugin that can verify tokens on the fly.

**Concept recap – JWT:** A JWT is a token containing JSON claims (like user identity, expiry time) that is **signed by a secret or private key**. It has three parts – a header, payload, and signature – encoded as Base64 and separated by dots. For example, a JWT might look like `xxxxx.yyyyy.zzzzz`. Kong’s JWT plugin will decode and verify the signature using a public key or secret associated with the token’s issuer. If the token is valid and not expired, Kong will allow the request; otherwise, it returns 401.

![img](blob:https://chatgpt.com/a03500d1-dd80-40d4-a358-bf1265e200bd) *Figure: Structure of a JWT. It consists of a header, payload, and signature. Each part is Base64Url encoded. The header typically contains the token type and signing algorithm; the payload contains claims (like `iss` issuer, `sub` subject/user, and `exp` expiration); the signature is created by signing the header+payload with a secret or private key.*

**Kong’s JWT plugin setup:** Kong ties JWTs to *Consumers*. A **Consumer** in Kong represents a client or user account in the context of the gateway. We create consumers and then associate credentials (like JWT public keys) with them. The JWT plugin will map a token to a consumer by matching the token’s claims to the credentials.

Steps to secure our route with JWT:

**1. Create a Consumer:** We’ll set up a consumer in Kong for our demo user.

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers `
  --data "username=demo-user"
```

This registers a consumer identified by `demo-user`. (The name is arbitrary; it could be an actual username or client name in a real scenario.)

**2. Generate a key pair (RSA):** For JWT, we need a key to sign tokens. We’ll use RSA for asymmetric signing (so the gateway can hold the **public key** and verify tokens signed by the **private key**). You can generate keys using OpenSSL or an online tool:

- Using OpenSSL (on Linux/Mac or Windows WSL):

  ```
  openssl genrsa -out private.key 2048
  openssl rsa -in private.key -pubout -out public.pem
  ```

  This yields `private.key` and `public.pem`.

- *(Alternatively, an online generator or library can produce these. The key is to have a private/public key pair.)*

**3. Associate the JWT credential with the Consumer:** We will tell Kong the public key that corresponds to tokens for `demo-user`. This is done via the consumer’s JWT credentials endpoint:

```
curl.exe -k -X POST "https://127.0.0.1:<admin-port>/consumers/demo-user/jwt" `
  --data "algorithm=RS256" `
  --data "key=demo-key" `
  --data-urlencode "rsa_public_key=$(< public.pem)"
```

Let’s explain: `algorithm=RS256` (we’ll use RSA SHA-256 signatures), `key=demo-key` is an arbitrary key identifier (often set as the JWT “iss” claim for matching), and `rsa_public_key` is the actual public key content (we read the `public.pem` file and URL-encode it into the request). After this, Kong knows that any JWT with issuer `demo-key` should be verified with this public key and, if valid, associated to consumer `demo-user`.

Now, Kong is configured with a consumer and its JWT credential. Next:

**4. Enable the JWT plugin on our route:**

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<ROUTE_ID>/plugins `
  --data "name=jwt"
```

This tells Kong that the `/api/hello` route now requires JWT auth. The plugin will look for an `Authorization: Bearer <token>` header in requests. If absent or invalid, the request will be rejected with 401. If present and valid, Kong will consider the consumer authenticated and allow the request to proceed (also, Kong will set `X-Consumer-Username: demo-user` on the upstream request, which could be used for logging or upstream logic if needed).

At this point, the route is locked down – any request without a proper token will get a `401 Unauthorized` from Kong. Let’s obtain a token to test:

**5. Create a JWT for testing:** We have the private key from earlier. We need to create a token signed with it. The token’s **claims** must include:

- `iss: "demo-key"` – this must match the `key` we gave Kong (so Kong knows to use the corresponding public key).
- `sub: "demo-user"` – the subject (who the token represents). Optional but we’ll include it for clarity.
- `exp: <future timestamp>` – expiration time. We should set this to some time in the future (e.g., current time + 10 minutes or +1 hour) so the token is valid.

There are a couple ways:

- **Manual (jwt.io):** Go to jwt.io. In the debugger, set the header to `{"alg":"RS256","typ":"JWT"}` and payload to `{"iss":"demo-key","sub":"demo-user","exp": <future UNIX time>}`. Then paste your **private key** into the signing key section. It will generate a token string. Copy that token.

- **Python script:** If you prefer, use a library like PyJWT:

  ```python
  import jwt, datetime
  payload = {"iss": "demo-key", "sub": "demo-user", "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}
  token = jwt.encode(payload, open("private.key","r").read(), algorithm="RS256")
  print(token)
  ```

  This will output a JWT (as a byte string in Python; decode to string if needed).

Either way, get a token string (it will look like a long string with two dots). This token is signed with our private key, and Kong has the matching public key.

**6. Test an authenticated request:** In Postman, do a GET to `http://127.0.0.1:<proxy-port>/api/hello`. Under **Authorization** tab, choose “Bearer Token” and paste the JWT token. Send the request.

- If the token is valid, the request should succeed (status 200). The response from Flask might now include `"user":"demo-user"` if the OAuth2 Proxy was involved, but since here we are directly using Kong’s JWT (no OAuth2 Proxy yet), our Flask app might not see a forwarded user. However, Kong will forward the request. *(Kong by default doesn’t inject the consumer name into the request headers unless using an auth plugin that does so; the JWT plugin doesn’t automatically forward the JWT or consumer info to upstream, aside from consumer headers. We could configure it to forward the `iss` as an upstream header if needed.)* For our purposes, seeing a 200 response means the token was accepted.
- If the token was missing or wrong:
  - Missing token yields `HTTP 401 Unauthorized` with possibly a body `{"message":"Unauthorized"}`.
  - If the token’s signature doesn’t match, or `iss` isn’t recognized, Kong returns 401 as well.
  - If the token is expired (`exp` in the past), Kong returns 401 (with `{"message":"Unauthorized"}`).

We can simulate failure by sending no token or altering one character in the token to corrupt it.

Now our API endpoint is effectively **protected by JWT auth**. Only those with a valid token signed by our key can access it. This is a common pattern for service-to-service auth or user auth in microservices.

**7. Per-Consumer Rate Limiting:** Since we now have distinct consumers (the JWT ties requests to a consumer), we can refine rate limiting. Earlier, we set a global 5/min limit. Perhaps we want to allow each user to have their own quota. We can achieve this by applying the rate-limiting plugin on the **Consumer** entity instead of (or in addition to) the route.

For example, to set a rate limit of 3 requests/minute for the consumer `demo-user`:

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/consumers/demo-user/plugins `
  --data "name=rate-limiting" `
  --data "config.minute=3" `
  --data "config.policy=local"
```

Now, when `demo-user` calls the API, Kong will count their requests separately and enforce 3/min for them. Another consumer (if created) could have a separate counter. This is powerful because it means one heavy user won’t consume the entire API quota for others. For our single user demo, it just demonstrates that Kong can do per-user limits once authentication is in place.

To test this, you could remove or raise the global limit to not interfere, then try >3 requests with the token within a minute – the 4th should get 429. The `X-RateLimit-Remaining` header now would be tied to the consumer’s limit. Kong’s response headers also include `X-RateLimit-Limit-demo_user: 3` (if configured to show consumer-level, though this might be an enterprise feature; anyway the concept stands).

**Summary so far:** We have a locked-down API: the client must present a valid JWT and is limited to N requests per minute. We used Kong’s Admin API to dynamically configure all of this, showing how an ops team could adjust policies in real-time. The backend service hasn’t changed at all during this – all security was added at the gateway level.

## Step 7: OAuth2 Proxy Integration (GitHub OAuth Login)

The JWT approach assumed you can obtain a token out-of-band (we manually created one). In a user-facing scenario, you’d typically have an **OAuth2 Authorization Code flow** to let users log in via a web UI and get a token or session. To demonstrate this more interactive auth, we include an **OAuth2 Proxy** in our architecture.

**What is OAuth2 Proxy?** It’s a utility that acts as a reverse proxy requiring authentication. It supports providers like Google, GitHub, etc. Essentially, it intercepts requests, and if the user isn’t logged in, it redirects them to the OAuth provider. Upon return, it establishes a session (often via a secure cookie) and then forwards the original request to the upstream service (adding headers like the user’s login name).

In our setup:

- We configure OAuth2 Proxy to use **GitHub** as the OAuth provider. This requires creating a GitHub OAuth app (to get a Client ID and Secret) and configuring allowed callback URLs (likely pointing to our proxy).
- The OAuth2 Proxy will run inside K8s and proxy to our Flask API. Once authenticated, it will inject `X-Forwarded-User` (the GitHub username or email) which our Flask app can read.

**Deploy OAuth2 Proxy:** We have a manifest (oauth2-proxy deployment and service). Key settings in the config (often done via environment variables or a config file):

- The OAuth provider (GitHub) and the client ID/secret from our GitHub OAuth App.
- The cookie secret (random string for signing session cookies).
- The upstream URL (where to send authenticated requests) – in our case, the Flask API service.
- Allowed email domains or GitHub orgs (optional filters).
- The OAuth scopes and endpoints.

For example, an `oauth2-proxy.yaml` might include:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
spec:
  template:
    spec:
      containers:
      - image: quay.io/oauth2-proxy/oauth2-proxy:v7.4.0
        args:
        - --provider=github
        - --client-id=<GitHub_OAuth_ClientID>
        - --client-secret=<GitHub_OAuth_ClientSecret>
        - --cookie-secret=<random_32byte_secret>
        - --upstream="http://backend-api.default.svc.cluster.local:80"
        - --redirect-url="http://<MINIKUBE_HOST>:<PROXY_PORT>/oauth2/callback"
        - --cookie-domain=localhost
        - --cookie-secure=false
        - --email-domain="*"
        # etc...
```

This is an example; the actual config might differ slightly. The **redirect URL** needs to match what we registered in GitHub (here, it points to the route on our Kong proxy that will handle the callback – Kong will route `/oauth2/callback` to the proxy service).

We expose the OAuth2 Proxy on a NodePort as well (say on port 4180) for testing from the host. Alternatively, we could route it entirely behind Kong (for instance, make Kong route `/oauth2/*` to the oauth2-proxy service). There are a couple of integration patterns:

- **Separate subdomain or port:** In our case, using NodePort 4180 (or an alternative domain) to access the OAuth2 Proxy directly.
- **Kong as a single gateway:** Kong can route `/oauth2/...` paths to the OAuth2 Proxy and everything else to the backend. This requires multiple Kong routes with different upstream targets. For instance, route `/oauth2/(.*)` → oauth2-proxy service, and route `/api/hello` → backend (but perhaps only after auth).

For simplicity, we might expose OAuth2 Proxy on `localhost:4180` and use it as the main entry for authenticated access. Actually, from the readme snippetfile-uqmlnxgfnza9ad85zgi6b9, it appears they accessed the proxy directly at `http://localhost:4180/oauth2/start` to initiate login, and then used it at `http://localhost:4180/api/hello` with the cookie.

**Kong + OAuth2 Proxy flow:** Another approach is to have Kong always send `/api/hello` traffic to the OAuth2 Proxy first (making the proxy an upstream for that route), and the proxy then calls the backend. In this chain:

- Client calls Kong `/api/hello`.
- Kong (with no JWT plugin in this scenario) proxies to OAuth2 Proxy.
- OAuth2 Proxy sees no session -> redirects client to GitHub.
- After login, GitHub redirects client back to `/oauth2/callback` on Kong.
- Kong routes `/oauth2/callback` to OAuth2 Proxy (we need a Kong route for that).
- OAuth2 Proxy completes auth, sets cookie, and redirects user to the original `/api/hello`.
- Now user calls `/api/hello` again (perhaps automatically by the proxy’s redirect).
- This time, OAuth2 Proxy sees a valid session cookie and forwards the request to Flask, which returns "Hello" with the user info.

As you can tell, this is a bit complex to simulate via Postman alone (since Postman doesn’t handle browser redirects easily). In a live demo, one can use a real browser for the OAuth login part, then switch to Postman for API calls using the obtained session cookie.

**Configuring Kong for the OAuth2 Proxy:** We add Kong routes:

- `/oauth2/start` and `/oauth2/callback` should be proxied to the oauth2-proxy service. (The proxy typically handles `/oauth2/start` to begin auth and `/oauth2/callback` as the redirect URI.)
- The main API path `/api/hello` – we could either point directly to backend (with JWT plugin as we did) OR point to oauth2-proxy service (and let the proxy forward to backend). In the readme final step, they opted to skip JWT plugin and use OAuth2 Proxy entirely, meaning Kong’s route for `/api/hello` likely was reconfigured to go to oauth2-proxy (which in turn calls backend). This way, OAuth2 Proxy deals with auth via GitHub and manages its own session cookie.

So we can adjust Kong’s service for `/api/hello` to use the OAuth2 Proxy as upstream:
 For example:

```powershell
# (Reconfigure or add a new service for oauth2-proxy)
curl.exe -k -X PUT https://127.0.0.1:<admin-port>/services/backend-api `
  --data "url=http://oauth2-proxy.default.svc.cluster.local:80"
```

(This would repoint our existing service to the proxy, which then calls backend. Alternatively, create a new service and route for the oauth2 proxy and adjust accordingly.)

In practice, due to time, one might simply access the proxy’s NodePort directly for demonstration:

- Open `http://localhost:4180/oauth2/start` in a browser, go through GitHub login.
- The proxy sets a cookie `_oauth2_proxy` in your browser upon success.
- Then in Postman, call the OAuth2 Proxy’s URL for the API (bypassing Kong): e.g. `http://localhost:4180/api/hello` with the cookie from the browser. The result should be 200 OK with `"user":"<your_github_username>"` in the JSON.
- However, if we want Kong in the loop, we’d ensure calling through Kong on port 31234 (with Kong routing to proxy as described). The readme snippet suggests they used port 4180 directly (which was likely the proxy NodePort).

For clarity in the presentation, we can describe the conceptual flow without getting lost in the configuration details:

**Demo flow with OAuth2 (conceptual):**

1. **User initiates request** – e.g., browsing to `http://<KONG>/api/hello` (or hitting the endpoint in Postman without a token).
2. **Redirect to IdP** – The OAuth2 Proxy (via Kong) sees no session and redirects to GitHub login.
3. **User authenticates** – User logs in on GitHub and approves.
4. **Callback** – User is redirected back to the proxy (through Kong) at `/oauth2/callback` with an auth code. The proxy exchanges this for an access token (internally) and creates a session.
5. **Set session and forward** – The proxy sets a cookie `_oauth2_proxy` in the user’s browser as a sign of the session. It then either redirects the user to the original page or, if the original request was waiting, proceeds to forward it.
6. **Authorized request** – Now the user has a session. If they request `/api/hello` again (with the cookie present, which the browser sends), the OAuth2 Proxy will recognize the user and forward the request to the Flask API, including headers like `X-Forwarded-User: <GitHub username>`.
7. **Response** – The backend returns "Hello from backend API" along with the user information in JSON. This goes back through OAuth2 Proxy -> Kong -> to the user’s browser or client.

From the user’s perspective, after logging in, they get the API response. From Kong’s perspective, it’s just proxying to the auth service and then to backend; Kong itself didn’t validate JWT (in this approach) – the OAuth2 Proxy handled authentication. We essentially replaced the JWT plugin with an external auth service in this flow.

**Rate limiting per consumer with OAuth2:** Since OAuth2 Proxy by default doesn’t create Kong consumers automatically, one approach could be: treat each session or user as a consumer by some identifier (maybe GitHub username). If we had Kong’s OIDC plugin (enterprise), it could do that mapping. In our case, an easy demonstration is to apply a rate limit plugin on the OAuth2 Proxy’s route or service as a whole. Alternatively, since we know all traffic is from one user (you), our earlier rate limiting still works globally. For a more advanced setup, one could script the creation of a Kong consumer for each new OAuth2 user and tie it in – but that’s beyond a classroom demo scope. We can simply mention that **if multiple users access, Kong can still impose per-user limits** (with custom logic or enterprise features).

**Testing OAuth2 flow in the demo:**

- Have a web browser ready to perform the login portion (since Postman can’t do interactive OAuth easily).
- After login, use Postman to make an API call with the session cookie, or simply show the result in the browser. The readme suggests copying the `_oauth2_proxy` cookie from browser dev tools and using it in Postmanfile-uqmlnxgfnza9ad85zgi6b9file-uqmlnxgfnza9ad85zgi6b9. This is a clever way to use Postman to test the authenticated call: you add a header `Cookie: _oauth2_proxy=<value>` in Postman, then GET the Kong/Proxy URL for `/api/hello`. If done right, you’ll see a 200 and the response with your user info, and Kong’s logs will show a successful pass.

We’ll ensure to highlight this in the presentation, possibly by doing a quick live login and then using that cookie in Postman to show the API output and also maybe the log entry in our mock log service.

*(At this stage, we have shown two methods of auth: static JWT and a real OAuth2 login flow. It underscores how Kong can work with both approaches – directly verifying tokens or delegating to an OAuth2 Proxy.)*

## Step 8: Monitoring and Logging the Requests

Aside from protecting APIs, an API gateway gives insight into traffic. We will demonstrate basic monitoring via logs:

**Kong Logging Plugin:** Kong can log requests to various endpoints (file, syslog, HTTP, etc.). We use the **http-log plugin** to send logs of each request to a dummy HTTP endpoint (httpbin). This simulates how you might send logs to an external logging service.

We deploy a **mock logging service** (in the readme, they used `kennethreitz/httpbin` image) inside the cluster:

```
kubectl run mock-logger --image=kennethreitz/httpbin --port=80
kubectl expose pod mock-logger --name=mock-logger --port=80
```

This gives us a service `mock-logger` that basically will echo any requests it receives (httpbin has an endpoint `/post` that just logs the posted data).

Now enable the plugin on our route:

```powershell
curl.exe -k -X POST https://127.0.0.1:<admin-port>/routes/<ROUTE_ID>/plugins `
  --data "name=http-log" `
  --data "config.http_endpoint=http://mock-logger.default.svc.cluster.local/post" `
  --data "config.method=POST"
```

This config means: for every request on this route, Kong will asynchronously POST a JSON log to the httpbin service’s `/post` endpoint. The log includes details like route, consumer, response code, latency, etc.

To see it in action, we can `kubectl logs` the httpbin pod (mock-logger) to watch for incoming posts. Then, when we make some requests to our API (either JWT-authenticated ones or via OAuth2 Proxy with cookie), Kong will send logs. We should see in httpbin’s output the entries for each request.

For example, a log entry might contain the consumer (‘demo-user’), the path `/api/hello`, response time, response code 200, etc. We can show these logs to the audience to illustrate how Kong provides observability.

**Kong Manager (UI):** Note that Kong OSS primarily is configured via API/CLI, but there is an add-on GUI (Kong Manager) in Kong Enterprise. We won’t have that here, but it’s worth mentioning that in a real scenario, a web dashboard could be used for some of this. Our focus is on the open-source tooling (Admin API, kubectl, logs, Postman).

**Postman for tracing:** We have already used Postman to simulate requests. We can also use it to see headers (as we did for rate limit) and to organize a collection of test calls:

- One request for an unauthenticated call (expect 401 after JWT plugin enabled).
- One with token (expect 200).
- A runner sending multiple calls to hit rate limit (Postman can do limited scripting or we do that manually).
- A request including the cookie for OAuth2 (to show 200 with user info).
   We can save these and show each working or failing as expected, giving a clear picture of the policies in effect.

Finally, **monitoring the cluster:** We should keep an eye on Minikube’s dashboard or use `kubectl get pods` to show everything running (Kong, Postgres, OAuth2 Proxy, backend, logger). If something fails, logs (`kubectl logs <pod>`) are the first place to check. For instance, if OAuth2 Proxy isn’t redirecting correctly, its logs would show what’s wrong (maybe a redirect URL mismatch). If Kong’s not forwarding, Kong’s logs might show route or plugin errors.

## Suggested Presentation Flow & Team Responsibilities

This project is rich in content, suitable for a ~2 hour session. To manage time and keep it engaging, the work can be split among team members, each focusing on specific aspects:

- **Presenter 1 – Introduction & Theory:** Explain the core concepts of API gateways, authentication, and rate limiting. This includes the slides on what Kong/Tyk are, why we use JWT/OAuth, and the high-level architecture diagram. This sets the stage for the demo. (This person can use the conceptual diagram to discuss how an API Gateway fits in a microservice environment, and cite examples[descope.com](https://www.descope.com/blog/post/kong-gateway-authentication#:~:text=An API gateway is a,track service performance and availability)[descope.com](https://www.descope.com/blog/post/kong-gateway-authentication#:~:text=The Kong Gateway is a,seamless API integration and high).)

- **Presenter 2 – Backend Service & Environment Setup:** Cover Step 1 and 2 – the Flask API, how it was containerized, and deployed on Minikube. Show a snippet of `app.py` and the Docker build process. Then explain how Minikube is set up and how we verified the backend is running (perhaps a quick `curl` to the service). This gives the audience an understanding of the baseline app we are protecting.

- **Presenter 3 – Kong Deployment & Configuration:** Walk through installing Kong (Helm basics, the values used) and then demonstrate adding the service and route via Admin API. This is a great place to do a live curl or use a REST client to show how we tell Kong about the backend. After configuring, do the first test through Kong (show that without plugins, the gateway simply proxies the request). Highlight how Kong is configured declaratively via these API calls (or could be via config files too), similar to how one would in a real deployment.

- **Presenter 4 – Security Policies (Plugins):** Introduce the plugins. Possibly split this into two sub-parts:

  - **Rate Limiting:** Show how the plugin is enabled and test the effect. This can be a quick live demo: send multiple requests (maybe using a quick Postman runner or a shell loop) and then show the 429 response and the headers. Explain the significance of those headers.
  - **JWT Authentication:** Explain JWT briefly (possibly referencing the JWT structure image) and then show how we set up the JWT plugin. This could be partly slides (for concept) and partly demo (maybe pre-generated token to avoid doing it live, but you can show the contents of a token on jwt.io). Then demonstrate a call without token (gets 401) vs with token (gets 200).
  - Emphasize that now we have **both** auth and rate-limit – if time, show that exceeding limit with a valid token still gives 429 (which means the plugins are working in tandem).

  Because JWT setup is a bit fiddly (especially generating the token), this presenter should prepare the token beforehand and perhaps just explain how it was generated.

- **Presenter 5 – OAuth2 Login Integration & Logging:** Finally, cover the OAuth2 Proxy integration as a more “real-world” auth scenario. This part can be a bit complex, so the presenter should carefully explain the flow with a diagram or sequence: user -> GitHub -> etc. Then perhaps do a live mini-demo: open browser to log in via OAuth2 Proxy (GitHub). After login, copy the cookie to Postman and show an API call succeeding with that cookie. This proves the concept. They should also mention how this relates to the gateway (if Kong is routing to the proxy or if we used the proxy as a separate endpoint in the demo).

  - Also cover the **logging plugin**: show logs being produced for requests. If possible, demonstrate that after making the requests, the `mock-logger` service received a POST (perhaps by showing `kubectl logs mock-logger`). This closes the loop, showing we not only protected the API but also have visibility into calls.
  - If any metric or Kong Manager UI was available, mention it, but primarily we’ll stick to logs.

Throughout the demo, all presenters should coordinate transitions. For example, Presenter 3 (Kong config) can hand off to Presenter 4 by saying “Now that Kong is forwarding requests, let’s secure it – [Name], can you show how we add auth and rate limiting?”. Similarly, Presenter 4 can hand to 5 by saying “We used a static token for JWT; in a real app, users would log in – [Name] will show how we integrated GitHub login using an OAuth2 Proxy.”

Everyone should be familiar with the entire flow, as questions could pop up at any point. The division is mainly to distribute speaking roles:

- **Slide content:** likely covered by Presenter 1 (theory) and a bit by others when introducing their parts.
- **Live terminal/Kong admin tasks:** Presenter 3 and 4 might be at the terminal showing `curl` commands and Postman.
- **Live browser demo:** Presenter 5 for OAuth2 login.

Backup each live step with a prepared result (screenshots or pre-recorded short clip) in case something doesn’t work (Minikube can be finicky under pressure).

## Troubleshooting Tips and Best Practices

Setting up this demo in Minikube involves multiple components. Here are some tips to avoid or resolve common issues:

- **Minikube Setup:** Use a consistent driver (docker) and allocate enough memory/CPUs if possible (`minikube start --cpus=4 --memory=4g` for example) since we’re running a database, Kong, etc. If something isn’t working, `minikube status` and `kubectl get pods -A` can show if a pod is CrashLooping (e.g., Kong’s database migration failed).
- **Helm/Kong Issues:** If `helm install kong ...` hangs or fails, check if you might still have an old installation. Running `helm uninstall kong -n kong` to remove any previous release and then reinstall can help. Ensure your values enable the Admin API – without it, you won’t be able to POST routes/services. Also, if the Admin API is on HTTPS (which it is by default), remember to use `-k` to ignore the self-signed cert, or configure Kong with an environment variable to allow HTTP on admin (not recommended in real scenarios, but okay locally).
- **Kong Admin API connectivity:** If `minikube service kong-kong-admin --url` returns an address that isn’t working, you can try `kubectl port-forward svc/kong-kong-admin -n kong 8001:8001` to map it to localhost:8001. Similarly for proxy (8000:80 or such). Sometimes NodePorts on Minikube with certain drivers might be less accessible – port-forward is a straightforward fallback for accessing services.
- **Backend API not reachable by Kong:** If Kong returns an error when proxying, it might mean it cannot resolve `backend-api.default.svc.cluster.local`. Make sure the service name and namespace are correct. If you named the service differently or deployed to another namespace, update the URL in Kong’s service. You can exec into the Kong pod (`kubectl exec -it <kong-pod> -n kong -- ping backend-api.default.svc.cluster.local`) to test DNS resolution inside the pod.
- **JWT token issues:** Common problems are mismatched `iss` or wrong keys. Remember:
  - The `iss` claim in the JWT must match the `key` field in Kong’s consumer JWT credential.
  - Use correct RSA keys and include the `-----BEGIN PUBLIC KEY-----` and end lines when uploading the public key (unless using HTTP API with proper encoding, as we did).
  - Check token expiration (`exp`). If the token is expired or not set, Kong will reject it. For testing, you can set a long exp (or re-generate if time passes).
  - If using an online generator like jwt.io, ensure you select RS256 and paste the **private key** to sign. Also double-check no trailing spaces in the key input.
- **OAuth2 Proxy setup:** This is likely the trickiest part.
  - Make sure the **GitHub OAuth App** is configured with the correct callback URL (whatever your environment uses, e.g., `http://localhost:4180/oauth2/callback` if going directly, or Kong’s proxy URL if going through Kong).
  - The OAuth2 Proxy needs the client ID/secret from GitHub. If those are wrong, you’ll get an immediate error page on trying to log in.
  - If login succeeds but the `/api/hello` still says unauthorized, it could be the cookie not being sent. For Postman, copying the cookie manually is needed. In a browser, the cookie domain and secure flags must be set such that it’s sent. In our config, we allowed it for domain `localhost` and not secure (since we’re on http).
  - You might consider running `kubectl logs deploy/oauth2-proxy` to watch its output during login – it will often log what it’s doing or any errors (like “invalid cookie signature” or “no valid token found” etc).
  - If using Kong to route to the proxy, ensure Kong’s route for `/oauth2/*` has `strip_path=false` as well (since OAuth2 Proxy expects those paths intact).
- **Synchronization of Plugins:** Sometimes after adding a plugin, it might take a brief moment to propagate. Ensure your curls/Postman tests happen after you got a response from the Admin API. Kong typically applies changes immediately, but keep an eye on response codes.
- **Time management in demo:** The OAuth2 login can take a bit of time (especially the first time you authenticate with your app on GitHub). To keep things smooth, one presenter can initiate the OAuth login in the background while another is explaining something else, so that by the time we need to demonstrate the result, the login is done. Alternatively, have a session already established (cookie) so you can directly show the authenticated call, then if needed, logout and show the redirect flow if time permits.
- **Backup Plans:** Have screenshots ready for critical steps (e.g., Postman showing a 429 response with headers, jwt.io screen with the token, GitHub login page, etc.). In case live Minikube or internet fails, these can still convey what happened. For example, if GitHub OAuth is down or unreachable (internet issues), explain the flow verbally and perhaps show a pre-saved response.
- **Clean-up and Re-deploy:** If things go really wrong, having a script (`setup_guide.md` or an init script) that tears down and sets up the known-good configuration can save time. Minikube can be reset with `minikube delete` (though that’s heavy-handed). Ideally, keep all YAML and command steps in order so you can retrace if needed.

Lastly, remember to **practice the demo** as a team. Ensure each person’s part works and you know how to recover if a step fails. Given the multiple moving parts, dry runs will help catch environment-specific quirks. With good preparation, this comprehensive demo will impress the audience, showing how API gateways like Kong provide a robust solution for scalable API management with security and monitoring features built-in. Good luck, and enjoy demonstrating your “secure mini-API platform” on June 2nd!