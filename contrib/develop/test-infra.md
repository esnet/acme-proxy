# Test Infrstructure using Docker containers

1. Build the container image from project root and start the server

```sh
git clone --recurse-submodules git@github.com:esnet/acme-proxy.git
docker build -t acme-proxy:latest .
```

2. If you are running Docker on a Linux host then run the following commands. If on MacOS, jump to 3.

```sh
mkdir -p /opt/acme-proxy/db
touch /opt/acme-proxy/ca.json
chown -R 65532:65532 /opt/acme-proxy
```

3. Start the container with appropriate mounts

```sh
docker run -d \
  --name acme-proxy-test \
  -p 8443:443 \
  -v "$(pwd)"/ca.json:/opt/acme-proxy/ca.json:ro \
  -v "$(pwd)"/db:/opt/acme-proxy/db \
  --restart unless-stopped \
  acme-proxy:latest
```
