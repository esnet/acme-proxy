# Setting up end to end test infrastructure for CI

This document contains my thought process for the CI infrastructure we'd like to setup to run end to end automated tests before merging changes to the main branch.

1. Build the container image from project root and start the server

```sh
git clone git@github.com:esnet/acme-proxy.git
docker build -t acme-proxy:latest .
docker network create acme-proxy-testbridge
```

2. These commands are only required for Linux. MacOS users can skip this.

```sh
mkdir -p /opt/acme-proxy/db
touch /opt/acme-proxy/ca.json
chown -R 65532:65532 /opt/acme-proxy
```

3. We can claim a free domain for one testing purposes using one of the following free DNS providers which are also supported by Lego! I created a free account & called dibs on `acme-proxy.duckdns.org`

- [DuckDNS](https://www.duckdns.org/)
- [IPv64](https://ipv64.net)
<br>

4. Configure ca.json for DNS01-TXT challenge with LetsEncrypt as the signing CA. One downside to using LetsEncrypt is they rate limit their api. Another potential option here is to have one more running container which runs step-ca or Pebble as a mock signing authority which will give us fake certs. Now the downside to _this_ approach is we'd need to configure the whole trust chain.

```json
"config": {
      "ca_url": "https://acme-v02.api.letsencrypt.org/directory",
      "account_email": "certadmins@duckdns.org",
      "eab_kid": "",
      "eab_hmac_key": "",
      "dns01_txt":{
        "provider":"duckdns",
        "dns_servers":["ns1.duckdns.org", "ns2.duckdns.org"],
        "env_vars":{
          "DUCKDNS_TOKEN": "0ur#sup3r-s3cr37-t0ken!"
        }
      },
```

5. Start the container with appropriate mounts. Run this command from the project root.
```sh
docker run -d --name acme-proxy.duckdns.org \
  -v "$(pwd)"/ca.json:/opt/acme-proxy/ca.json:ro \
  -v "$(pwd)"/db:/opt/acme-proxy/db \
  --restart unless-stopped \
  --publish 8443:443 \
  --network acme-proxy-testbridge \
  acme-proxy:latest
```

6. Start a new container on the same docker bridge that runs lego as an acme client to request certificates.

```sh
docker run \
  --name ci-test.acme-proxy.duckdns.org \
  --network acme-proxy-testbridge \
  goacme/lego:v5.3.1 run \
    --server https://acme-proxy.duckdns.org/acme/acme/directory \
    --domains ci-test.acme-proxy.duckdns.org \
    --email certadmins@duckdns.org \
    --accept-tos \
    --http
```

5. teardown and cleanup
```sh
docker kill acme-proxy
docker rm lego-acme.networkninja.dev acme-proxy-test.networkninja.dev
docker network rm acme-proxy-testbridge
```
