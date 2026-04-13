+++
title = 'User Guide'
weight = 30
BookToC = true
+++

# User Guide

This guide covers how to obtain and automatically renew TLS certificates from `acme-proxy` using three common ACME clients: [acme.sh](https://github.com/acmesh-official/acme.sh), [Certbot](https://certbot.eff.org/), and [Lego](https://go-acme.github.io/lego/).

**ACME directory URL:**

```
https://acme-proxy.example.com/acme/acme/directory
```

Replace `acme-proxy.example.com` with your organization's actual acme-proxy hostname.

---

## Table of Contents

- [1. NGINX on Linux VM / Baremetal](#1-nginx-on-linux-vm--baremetal)
- [2. Apache on Linux VM / Baremetal](#2-apache-on-linux-vm--baremetal)
- [3. Standalone Mode](#3-standalone-mode-databases-redis-kafka-etc)
- [4. Docker and Docker Compose](#4-docker-and-docker-compose)
- [5. Kubernetes (cert-manager)](#5-kubernetes-cert-manager)

---

## Prerequisites

- The ACME client must be installed and an account registered with acme-proxy before running any commands in this guide. See [admin.md](./admin.md) for installation instructions and systemd renewal timer setup.
- Port 80 must be reachable from the acme-proxy server (used for HTTP-01 challenge validation).
- Your domain's DNS must resolve to the host where the ACME client runs.
- Replace the following placeholders throughout this guide:
  - `acme-proxy.example.com` — your acme-proxy hostname
  - `myserver.example.com` — the domain you want a certificate for
  - `admin@example.com` — your contact email

---

## 1. NGINX on Linux VM / Baremetal

### 1a. acme.sh

**Register and issue a certificate (single domain):**

```bash
acme.sh --register-account \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --email admin@example.com

acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --nginx \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --nginx \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com
```

**Install the certificate and configure auto-reload:**

```bash
acme.sh --install-cert -d myserver.example.com \
  --cert-file     /etc/nginx/ssl/myserver.example.com.crt \
  --key-file      /etc/nginx/ssl/myserver.example.com.key \
  --fullchain-file /etc/nginx/ssl/myserver.example.com-fullchain.crt \
  --reloadcmd     "systemctl reload nginx"
```

**Auto-renewal:** The systemd timer configured in [admin.md](./admin.md) drives renewal. acme.sh executes the `--reloadcmd` above after each successful renewal.

---

### 1b. Certbot

**Register and issue a certificate (single domain):**

```bash
sudo certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
sudo certbot --nginx \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com
```

**Auto-renewal:** Managed by the certbot systemd timer. See [admin.md](./admin.md) for timer setup and log configuration.

---

### 1c. Lego

Lego uses webroot mode with NGINX — the ACME challenge files are written to NGINX's document root and served over port 80.

**Ensure NGINX serves the challenge path** — add this to your NGINX server block if not already present:

```nginx
location /.well-known/acme-challenge/ {
    root /var/www/html;
}
```

**Issue a certificate (single domain):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  --http.webroot /var/www/html \
  -d myserver.example.com \
  run
```

**Issue for multiple domains (SAN certificate):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  --http.webroot /var/www/html \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com \
  run
```

Certificates are saved to `~/.lego/certificates/`.

**Configure NGINX** to use the issued certificate:

```nginx
ssl_certificate     /root/.lego/certificates/myserver.example.com.crt;
ssl_certificate_key /root/.lego/certificates/myserver.example.com.key;
```

**Auto-renewal:** Managed by the systemd timer configured in [admin.md](./admin.md). Ask your admin to add `--renew-hook 'systemctl reload nginx'` to the lego renewal script for this domain.

---

## 2. Apache on Linux VM / Baremetal

### 2a. acme.sh

**Register and issue a certificate (single domain):**

```bash
acme.sh --register-account \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --email admin@example.com

acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --apache \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --apache \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com
```

**Install the certificate and configure auto-reload:**

```bash
acme.sh --install-cert -d myserver.example.com \
  --cert-file     /etc/ssl/certs/myserver.example.com.crt \
  --key-file      /etc/ssl/private/myserver.example.com.key \
  --fullchain-file /etc/ssl/certs/myserver.example.com-fullchain.crt \
  --reloadcmd     "systemctl reload apache2"
```

> On RHEL-based systems use `httpd` instead of `apache2`.

**Auto-renewal:** The systemd timer configured in [admin.md](./admin.md) drives renewal. acme.sh executes the `--reloadcmd` above after each successful renewal.

---

### 2b. Certbot

**Register and issue a certificate (single domain):**

```bash
sudo certbot --apache \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
sudo certbot --apache \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com
```

**Auto-renewal:** Managed by the certbot systemd timer. See [admin.md](./admin.md) for timer setup and log configuration.

---

### 2c. Lego

Ensure Apache serves the challenge path. Add this to your VirtualHost configuration:

```apache
Alias /.well-known/acme-challenge/ /var/www/html/.well-known/acme-challenge/
<Directory /var/www/html/.well-known/acme-challenge/>
    Options None
    AllowOverride None
    Require all granted
</Directory>
```

**Issue a certificate (single domain):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  --http.webroot /var/www/html \
  -d myserver.example.com \
  run
```

**Issue for multiple domains (SAN certificate):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  --http.webroot /var/www/html \
  -d myserver.example.com \
  -d www.myserver.example.com \
  -d api.myserver.example.com \
  run
```

**Configure Apache** to reference the certificates:

```apache
SSLCertificateFile    /root/.lego/certificates/myserver.example.com.crt
SSLCertificateKeyFile /root/.lego/certificates/myserver.example.com.key
```

**Auto-renewal:** Managed by the systemd timer configured in [admin.md](./admin.md). Ask your admin to add `--renew-hook 'systemctl reload apache2'` (or `httpd` on RHEL-based systems) to the lego renewal script for this domain.

---

## 3. Standalone Mode (Databases, Redis, Kafka, etc.)

Standalone mode runs a temporary HTTP server on port 80 to answer the ACME challenge. Use this when there is no existing web server — typical for backend services such as Databases, Redis, Kafka, etc.

> Port 80 must be temporarily available on the host. If IPtables or network firewall is in place, they must allow incoming http traffic from acme-proxy to the host.

### 3a. acme.sh

> acme.sh's standalone mode requires `socat`. The deb/rpm package may not install it on all distributions. Verify it is present before proceeding:
>
> ```bash
> socat -V 2>/dev/null || echo "socat not found — install with: apt-get install socat / dnf install socat"
> ```
>
> Certbot and lego (sections 3b and 3c) use their own built-in HTTP servers and do not require socat.

**Register and issue a certificate (single domain):**

```bash
acme.sh --register-account \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --email admin@example.com

acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --standalone \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --standalone \
  -d myserver.example.com \
  -d myserver-alt.example.com
```

**Install the certificate to a standard location:**

```bash
acme.sh --install-cert -d myserver.example.com \
  --cert-file      /etc/ssl/certs/myserver.example.com.crt \
  --key-file       /etc/ssl/private/myserver.example.com.key \
  --fullchain-file /etc/ssl/certs/myserver.example.com-fullchain.crt \
  --reloadcmd      "systemctl reload <your-service>"
```

**Auto-renewal:** The systemd timer configured in [admin.md](./admin.md) drives renewal. During each renewal attempt, acme.sh will again bind port 80 briefly — ensure no other process occupies it at the scheduled renewal time.

---

### 3b. Certbot

**Register and issue a certificate (single domain):**

```bash
sudo certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com
```

**Issue for multiple domains (SAN certificate):**

```bash
sudo certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --server https://acme-proxy.example.com/acme/acme/directory \
  -d myserver.example.com \
  -d myserver-alt.example.com
```

Certificates are stored in `/etc/letsencrypt/live/myserver.example.com/`.

**Configure your service** to load certificates from:

```
/etc/letsencrypt/live/myserver.example.com/fullchain.pem
/etc/letsencrypt/live/myserver.example.com/privkey.pem
```

**Configure the service reload hook:**

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-service.sh <<'EOF'
#!/bin/bash
systemctl reload <your-service>
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-service.sh
```

Certbot executes this script after each successful renewal. The systemd timer that triggers renewal is configured in [admin.md](./admin.md).

---

### 3c. Lego

**Issue a certificate (single domain):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  -d myserver.example.com \
  run
```

**Issue for multiple domains (SAN certificate):**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  -d myserver.example.com \
  -d myserver-alt.example.com \
  run
```

Certificates are saved to `~/.lego/certificates/`.

**Auto-renewal:** Managed by the systemd timer configured in [admin.md](./admin.md). Ask your admin to add `--renew-hook 'systemctl reload <your-service>'` to the lego renewal script for this domain.

---

## 4. Docker and Docker Compose

This section covers the pattern for services already running as Docker containers or Docker Compose stacks. The ACME client runs on the **host** — not inside a container. Certificates are stored on the host filesystem and projected into running containers as read-only volume mounts. After renewal, the host-side renewal hook signals the affected containers to reload or restart.

```
Host ACME client  →  /etc/ssl/acme/<domain>/  →  volume mount  →  container
       ↓
  renewal hook  →  docker compose exec / docker compose restart
```

### Port 80 and running containers

The HTTP-01 challenge requires port 80 to be reachable. If a container already binds port 80 on the host, standalone mode cannot be used directly. Two approaches:

**Option A — stop the container briefly (standalone mode):**
Use pre- and post-hooks to stop the container before the challenge and restart it after. This causes a brief downtime window and is suitable for backend services where a short gap is acceptable.

**Option B — webroot via a shared bind mount:**
Mount a host directory (e.g., `/var/www/acme-challenge`) into the container at the path it serves for HTTP. The ACME client writes challenge files to that host directory; the container serves them. No downtime required. Use this when continuous availability on port 80 is required.

The examples below use Option A (standalone) for simplicity. Substitute webroot flags if you need Option B.

---

### Step 1 — Issue the initial certificate on the host

Use any of the client commands from the [Standalone Mode](#3-standalone-mode-databases-redis-kafka-etc) section, substituting a `--reloadcmd` / deploy hook that operates on Docker instead of systemd. For example, with acme.sh:

```bash
# Stop the container so port 80 is free for the challenge
docker compose -f /path/to/docker-compose.yml stop myapp

acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --standalone \
  -d myserver.example.com

# Start the container again
docker compose -f /path/to/docker-compose.yml start myapp
```

Install the certificate to a fixed host path:

```bash
sudo mkdir -p /etc/ssl/acme/myserver.example.com

acme.sh --install-cert -d myserver.example.com \
  --cert-file      /etc/ssl/acme/myserver.example.com/cert.pem \
  --key-file       /etc/ssl/acme/myserver.example.com/key.pem \
  --fullchain-file /etc/ssl/acme/myserver.example.com/fullchain.pem
```

---

### Step 2 — Mount the certificate directory into your containers

Add a read-only bind mount for the host certificate path in your `docker-compose.yml`:

```yaml
services:
  myapp:
    image: your-app-image
    ports:
      - "443:443"
    volumes:
      - /etc/ssl/acme/myserver.example.com:/etc/ssl/app:ro
    environment:
      TLS_CERT: /etc/ssl/app/fullchain.pem
      TLS_KEY:  /etc/ssl/app/key.pem
    restart: unless-stopped
```

Configure your application to load the TLS certificate from `/etc/ssl/app/` inside the container. The exact configuration depends on the application.

---

### Step 3 — Auto-renewal with container reload hook

After each renewal, the certificate files on the host are updated. The container must either reload its TLS configuration or restart to pick them up. Configure the appropriate hook for each ACME client.

#### acme.sh

```bash
acme.sh --install-cert -d myserver.example.com \
  --cert-file      /etc/ssl/acme/myserver.example.com/cert.pem \
  --key-file       /etc/ssl/acme/myserver.example.com/key.pem \
  --fullchain-file /etc/ssl/acme/myserver.example.com/fullchain.pem \
  --reloadcmd      "docker compose -f /path/to/docker-compose.yml restart myapp"
```

acme.sh's cron job runs `--reloadcmd` automatically after each successful renewal. If your container supports graceful config reload (e.g., NGINX via `nginx -s reload`), use `exec` instead of `restart` to avoid downtime:

```bash
  --reloadcmd "docker compose -f /path/to/docker-compose.yml exec myapp nginx -s reload"
```

If port 80 is held by a container during renewal, add pre- and post-hooks:

```bash
export Le_PreHook="docker compose -f /path/to/docker-compose.yml stop myapp"
export Le_PostHook="docker compose -f /path/to/docker-compose.yml start myapp"
acme.sh --renew -d myserver.example.com
```

#### Certbot

Create a deploy hook script that restarts the container after renewal:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/docker-reload.sh <<'EOF'
#!/bin/bash
docker compose -f /path/to/docker-compose.yml restart myapp
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/docker-reload.sh
```

If you need to stop the container for the challenge, use pre and post hooks:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/pre/docker-stop.sh <<'EOF'
#!/bin/bash
docker compose -f /path/to/docker-compose.yml stop myapp
EOF

sudo tee /etc/letsencrypt/renewal-hooks/post/docker-start.sh <<'EOF'
#!/bin/bash
docker compose -f /path/to/docker-compose.yml start myapp
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/pre/docker-stop.sh \
              /etc/letsencrypt/renewal-hooks/post/docker-start.sh
```

Enable the systemd timer as usual:

```bash
sudo systemctl enable --now certbot.timer
```

#### Lego

Use `--renew-hook` to restart the container after each successful renewal. Wrap the stop/start around the `renew` call in your cron entry:

```bash
sudo tee /etc/cron.d/lego-docker-renewal <<'EOF'
17 2 * * * root \
  docker compose -f /path/to/docker-compose.yml stop myapp && \
  lego \
    --server https://acme-proxy.example.com/acme/acme/directory \
    --accept-tos \
    --email admin@example.com \
    --http \
    -d myserver.example.com \
    renew \
    --renew-hook "docker compose -f /path/to/docker-compose.yml start myapp"
EOF
```

---

## 5. Kubernetes (cert-manager)

cert-manager is a Kubernetes-native certificate controller that speaks ACME natively. It handles account registration, order submission, challenge validation, and automatic renewal without any per-host tooling.

**How HTTP-01 works with cert-manager:**

1. cert-manager creates a temporary solver Pod and an `HTTPRoute` for `/.well-known/acme-challenge/<token>` attached to your Gateway
2. acme-proxy makes an HTTP request to `http://<domain>/.well-known/acme-challenge/<token>` to validate domain ownership
3. On success, cert-manager submits the CSR and retrieves the signed certificate
4. The certificate is stored in a Kubernetes Secret and renewed automatically before expiry

**Network requirement:** acme-proxy must be able to reach **port 80** on the cluster's Gateway. The domain must resolve to the Gateway's external IP.

### Prerequisites

- cert-manager v1.15+ — Gateway API support is enabled by default; earlier versions require `--feature-gates=ExperimentalGatewayAPISupport=true`
- Gateway API CRDs installed (`gateway.networking.k8s.io/v1`)
- A conformant Gateway implementation deployed (examples use `nginx` as the `gatewayClassName`; any v1-conformant implementation works)
- acme-proxy reachable from cert-manager pods on port 443 (for account registration and order submission)
- Port 80 of the Gateway reachable from acme-proxy (for HTTP-01 challenge validation)

---

### Step 1 — Create a Gateway

The Gateway must have an HTTP listener on port 80 to serve ACME challenges. cert-manager creates `HTTPRoute` objects in the same namespace as the `Certificate` (not the cert-manager namespace), so `allowedRoutes.namespaces.from: All` is required on the HTTP listener unless you restrict it to the specific namespaces where certificates are issued.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: infra
spec:
  gatewayClassName: nginx
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All        # cert-manager HTTPRoutes can originate from any namespace
  - name: https
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - name: myserver-tls
        namespace: infra
    allowedRoutes:
      namespaces:
        from: Same
```

---

### Step 2 — Create a ClusterIssuer

The `gatewayHTTPRoute` solver tells cert-manager which Gateway to attach challenge `HTTPRoute`s to.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: acme-proxy
spec:
  acme:
    server: https://acme-proxy.example.com/acme/acme/directory
    email: admin@example.com
    privateKeySecretRef:
      name: acme-proxy-account-key
    solvers:
    - http01:
        gatewayHTTPRoute:
          parentRefs:
          - name: my-gateway
            namespace: infra
            kind: Gateway
            group: gateway.networking.k8s.io
```

Apply and verify:

```bash
kubectl apply -f clusterissuer.yaml
kubectl get clusterissuer acme-proxy
```

Expected output:

```
NAME         READY   AGE
acme-proxy   True    30s
```

If `READY` is `False`, inspect the status conditions:

```bash
kubectl describe clusterissuer acme-proxy
```

A `False` state at this stage means account registration failed — check that acme-proxy is reachable from cert-manager pods and that the ACME directory URL is correct.

> **Do not delete the `acme-proxy-account-key` Secret.** It contains the private key for the registered ACME account. Deleting it forces re-registration and may orphan any in-flight orders.

---

### Step 3 — Issue a Certificate

Two approaches are supported depending on your workload type.

#### Option A — Gateway annotation (web workloads)

Add `cert-manager.io/cluster-issuer` to the `Gateway`. cert-manager detects the annotation and automatically creates a `Certificate` for each HTTPS listener that has a `hostname` set, storing the result in the listener's `certificateRefs` Secret.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: infra
  annotations:
    cert-manager.io/cluster-issuer: "acme-proxy"
spec:
  gatewayClassName: nginx
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
  - name: https
    hostname: myserver.example.com
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - name: myserver-tls
        namespace: infra
    allowedRoutes:
      namespaces:
        from: Same
```

Route application traffic with an `HTTPRoute` attached to the same Gateway:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: myapp
  namespace: default
spec:
  parentRefs:
  - name: my-gateway
    namespace: infra
  hostnames:
  - myserver.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    backendRefs:
    - name: myapp
      port: 80
```

#### Option B — Certificate resource (non-HTTP workloads)

Use this for workloads that consume TLS directly — gRPC services, databases, message brokers. cert-manager uses the Gateway to serve the HTTP-01 challenge but delivers the certificate into an arbitrary Secret.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: myserver-tls
  namespace: default
spec:
  secretName: myserver-tls
  issuerRef:
    name: acme-proxy
    kind: ClusterIssuer
  dnsNames:
  - myserver.example.com
```

Mount the resulting Secret into your Pod:

```yaml
volumes:
- name: tls
  secret:
    secretName: myserver-tls
containers:
- name: myapp
  volumeMounts:
  - name: tls
    mountPath: /etc/tls
    readOnly: true
```

The Secret contains `tls.crt` (full chain) and `tls.key`.

---

### Step 4 — Verify

Watch the certificate reach `Ready` state:

```bash
kubectl get certificate myserver-tls -w
```

Once `READY=True`, inspect the issued certificate:

```bash
kubectl get secret myserver-tls \
  -o jsonpath='{.data.tls\.crt}' \
  | base64 -d \
  | openssl x509 -noout -issuer -subject -dates
```

---

### Troubleshooting

If the certificate stays in `False` or `Issuing` state, follow the cert-manager object chain — each level narrows down where the failure occurred:

```bash
kubectl describe certificate myserver-tls -n default
kubectl get certificaterequest -n default
kubectl describe certificaterequest <name> -n default
kubectl get order -n default
kubectl describe order <name> -n default
kubectl get challenge -n default
kubectl describe challenge <name> -n default
```

The `Challenge` object's status message identifies the exact failure:

| Symptom | Likely cause |
|---------|-------------|
| `ClusterIssuer` not ready | acme-proxy unreachable from cert-manager pods; wrong ACME directory URL |
| Challenge stays `pending` | acme-proxy cannot reach the Gateway on port 80; domain DNS not pointing at the Gateway's external IP |
| Challenge `HTTPRoute` not attached | Gateway HTTP listener `allowedRoutes` does not include the namespace where the `Certificate` lives |
| Challenge fails with `connection refused` | HTTP listener missing on Gateway, or `parentRefs` in `ClusterIssuer` pointing to wrong Gateway name or namespace |
| `unauthorized` from ACME server | The `acme-proxy-account-key` Secret was deleted; recreate the `ClusterIssuer` to re-register |

---

## Pre and Post Hooks

Hooks let you run shell commands at specific points in the certificate lifecycle. The primary use cases are:

- **Freeing port 80** — standalone mode requires port 80 for the HTTP-01 challenge. If another process occupies it, use a pre-hook to stop it and a post-hook to restart it.
- **Reloading services after renewal** — so the renewed certificate is picked up without a full service restart.

The three clients use different hook mechanisms.

### Hook phases

| Phase | When it runs | Purpose |
|-------|-------------|---------|
| Pre-hook | Before the challenge attempt | Free port 80, drain connections |
| Post-hook | After the challenge, regardless of outcome | Restore services stopped by pre-hook |
| Deploy / renew hook | Only on successful issuance or renewal | Reload or restart the service using the certificate |

---

### acme.sh

acme.sh supports hooks via command-line flags or by setting environment variables that it persists in the per-domain config file (`~/.acme.sh/<domain>/<domain>.conf`).

**Command-line flags (apply once, persisted):**

```bash
acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --standalone \
  -d myserver.example.com \
  --pre-hook  "systemctl stop myapp" \
  --post-hook "systemctl start myapp" \
  --renew-hook "systemctl reload myapp"
```

These flags are written to the domain config and reused on every subsequent `--renew` run. You do not need to repeat them.

**Environment variables (equivalent to the flags above):**

```bash
export Le_PreHook="systemctl stop myapp"
export Le_PostHook="systemctl start myapp"
export Le_ReloadCmd="systemctl reload myapp"
acme.sh --renew -d myserver.example.com
```

**Verify hooks are saved:**

```bash
grep -E 'Le_PreHook|Le_PostHook|Le_ReloadCmd' ~/.acme.sh/myserver.example.com/myserver.example.com.conf
```

---

### Certbot

Certbot uses a directory-based hook model. Any executable script placed in these directories runs for all certificates:

| Directory | Phase |
|-----------|-------|
| `/etc/letsencrypt/renewal-hooks/pre/` | Before challenge |
| `/etc/letsencrypt/renewal-hooks/post/` | After challenge, regardless of outcome |
| `/etc/letsencrypt/renewal-hooks/deploy/` | On successful renewal only |

**Pre and post hooks (port 80 management):**

```bash
sudo tee /etc/letsencrypt/renewal-hooks/pre/stop-myapp.sh <<'EOF'
#!/bin/bash
systemctl stop myapp
EOF

sudo tee /etc/letsencrypt/renewal-hooks/post/start-myapp.sh <<'EOF'
#!/bin/bash
systemctl start myapp
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-myapp.sh \
              /etc/letsencrypt/renewal-hooks/post/start-myapp.sh
```

**Deploy hook (reload after renewal):**

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-myapp.sh <<'EOF'
#!/bin/bash
systemctl reload myapp
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-myapp.sh
```

Certbot passes `$RENEWED_DOMAINS` and `$RENEWED_LINEAGE` to deploy hooks, which lets you target specific certificates if multiple are managed:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/selective-reload.sh <<'EOF'
#!/bin/bash
if echo "$RENEWED_DOMAINS" | grep -q "myserver.example.com"; then
    systemctl reload nginx
fi
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/selective-reload.sh
```

Hooks can also be passed as one-shot flags to `certbot renew`:

```bash
sudo certbot renew \
  --pre-hook "systemctl stop myapp" \
  --post-hook "systemctl start myapp" \
  --deploy-hook "systemctl reload myapp"
```

---

### Lego

Lego supports hooks via `--run-hook` (runs after successful initial issuance) and `--renew-hook` (runs after successful renewal). There is no persistent hook state — you must pass hooks in every invocation or via a wrapper script.

**Issue with hooks:**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  -d myserver.example.com \
  run \
  --run-hook "systemctl reload myapp"
```

**Renew with hooks:**

```bash
lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  -d myserver.example.com \
  renew \
  --renew-hook "systemctl reload myapp"
```

For port 80 management, wrap the lego call in a script:

```bash
sudo tee /usr/local/sbin/lego-renew-myserver.sh <<'EOF'
#!/bin/bash
set -euo pipefail

systemctl stop myapp

lego \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --accept-tos \
  --email admin@example.com \
  --http \
  -d myserver.example.com \
  renew \
  --renew-hook "systemctl start myapp && systemctl reload myapp"

# Ensure myapp is always restarted even on failure
if ! systemctl is-active --quiet myapp; then
    systemctl start myapp
fi
EOF
sudo chmod 0700 /usr/local/sbin/lego-renew-myserver.sh
```

Lego passes the following environment variables to hook scripts:

| Variable | Value |
|----------|-------|
| `LEGO_ACCOUNT_EMAIL` | Account email |
| `LEGO_CERT_PATH` | Path to the certificate file |
| `LEGO_CERT_KEY_PATH` | Path to the private key file |
| `LEGO_CERT_DOMAIN` | Primary domain on the certificate |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `connection refused` on port 80 | Firewall blocking challenge traffic | Open port 80 from acme-proxy host |
| `no route to host` to acme-proxy | DNS not resolving or network ACL | Confirm the proxy hostname resolves and port 443 is reachable |
| Certificate issued but service won't reload | `--reloadcmd` / deploy hook misconfigured | Run the reload command manually; check service name |
| Renewal fails in standalone mode | Port 80 occupied during renewal window | Stop the process holding port 80 before renewal, or switch to webroot mode |
| `unauthorized` from ACME server | Account not registered with this server | Re-run `--register-account` against the correct `--server` URL |
