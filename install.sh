#!/bin/sh
set -e

REPO="esnet/acme-proxy"
CONFIG_DIR="/etc/acmeproxy"
DB_DIR="${CONFIG_DIR}/db"
CONFIG_FILE="${CONFIG_DIR}/ca.json"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Creating configuration directory..."
mkdir -p "$DB_DIR"

echo "Creating ca.json configuration file..."
cat > "$CONFIG_FILE" << 'EOF'
{
  "address": ":443",
  "dnsNames": ["acmeproxy.example.com"],
  "logger": {
    "format": "text"
  },
  "db": {
    "type": "badgerv2",
    "dataSource": "/etc/acmeproxy/db"
  },
  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "",
      "account_email": "",
      "eab_kid": "",
      "eab_hmac_key": "",
      "metrics": {
        "enabled": true,
        "port": 9123
      }
    },
    "provisioners": [
      {
        "type": "ACME",
        "name": "acme",
        "claims": {
          "enableSSHCA": false,
          "disableRenewal": false,
          "allowRenewalAfterExpiry": false,
          "disableSmallstepExtensions": true
        },
        "options": {
          "x509": {},
          "ssh": {}
        }
      }
    ],
    "template": {},
    "backdate": "1m0s"
  },
  "tls": {
    "minVersion": 1.1,
    "maxVersion": 1.2,
    "renegotiation": false
  },
  "commonName": "acmeproxy.example.com"
}
EOF

echo "Downloading latest release..."
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
BINARY_NAME="acme-proxy_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${BINARY_NAME}"

curl -L -o acme-proxy "$DOWNLOAD_URL"
chmod +x acme-proxy

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit ${CONFIG_FILE} and configure:"
echo "     - dnsNames: Your ACME proxy hostname"
echo "     - ca_url: Your upstream ACME CA URL"
echo "     - account_email: Your account email"
echo "     - eab_kid: External Account Binding Key ID (if required)"
echo "     - eab_hmac_key: External Account Binding HMAC key (if required)"
echo ""
echo "  2. Start the server:"
echo "     step-ca ${CONFIG_FILE}"
echo ""
