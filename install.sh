#!/bin/sh
set -e

REPO="esnet/acme-proxy"
INSTALL_DIR="${INSTALL_DIR:-/opt/acme-proxy}"
DB_DIR="${DB_DIR:-${INSTALL_DIR}/db}"
CONFIG_FILE="${CONFIG_FILE:-${INSTALL_DIR}/ca.json}"
SERVICE_USER="${SERVICE_USER:-acme-proxy}"
SERVICE_GROUP="${SERVICE_GROUP:-acme-proxy}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

# Check and install libpcsclite dependency
echo "Checking for libpcsclite dependency..."
OS_NAME=$(uname -s)
if [ "$OS_NAME" = "Darwin" ]; then
    echo "Found macOS - skipping dependency check"
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    if echo "$ID" | grep -Eqi 'ubuntu|debian'; then
        if ! dpkg -s libpcsclite-dev >/dev/null 2>&1; then
            echo "Installing libpcsclite-dev on Debian/Ubuntu..."
            apt-get update && apt-get install -y libpcsclite-dev
        else
            echo "libpcsclite-dev already installed"
        fi
    elif echo "$ID" | grep -Eqi 'rhel|rocky|centos'; then
        if ! rpm -q pcsc-lite-devel >/dev/null 2>&1; then
            echo "Installing pcsc-lite-devel on RHEL/Rocky/CentOS..."
            dnf install -y pcsc-lite-devel
        else
            echo "pcsc-lite-devel already installed"
        fi
    else
        echo "Warning: Unknown Linux distribution: $ID"
        echo "You may need to install pcsc-lite development libraries manually"
    fi
else
    echo "Warning: Cannot detect OS (/etc/os-release not found)"
    echo "You may need to install pcsc-lite development libraries manually"
fi

echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DB_DIR"

echo "Creating ca.json configuration file..."
cat > "$CONFIG_FILE" << EOF
{
  "address": ":443",
  "dnsNames": ["acmeproxy.example.com"],
  "logger": {
    "format": "json"
  },
  "db": {
    "type": "bbolt",
    "dataSource": "${DB_DIR}/bbolt"
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
BINARY_NAME="step-ca_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${BINARY_NAME}"

curl -L -o step-ca "$DOWNLOAD_URL"
chmod +x step-ca

echo "Installing binary to ${INSTALL_DIR}..."
mv step-ca "${INSTALL_DIR}/"

echo "Creating ${SERVICE_USER} service user..."
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# Create group if it doesn't exist and is different from user
if [ "${SERVICE_USER}" != "${SERVICE_GROUP}" ] && ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
    usermod -a -G "${SERVICE_GROUP}" "${SERVICE_USER}"
fi

echo "Setting ownership of installation directory..."
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$INSTALL_DIR"

echo "Installing systemd service..."
cat > /etc/systemd/system/acme-proxy.service << EOF
[Unit]
Description=ACME Proxy Server (step-ca)
Documentation=https://github.com/esnet/acme-proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}

# Paths
ExecStart=${INSTALL_DIR}/step-ca ${CONFIG_FILE}
WorkingDirectory=${INSTALL_DIR}

# Restart behavior
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=no
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes

# Allow binding to privileged ports (443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Allow write access to config and database directories
ReadWritePaths=${INSTALL_DIR}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=acme-proxy

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling acme-proxy service..."
systemctl enable acme-proxy

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit ${CONFIG_FILE} and configure:"
echo "     - dnsNames: Your ACME proxy hostname"
echo "     - ca_url: Your upstream ACME CA URL"
echo "     - account_email: Your account email"
echo "     - eab_kid: External Account Binding Key ID"
echo "     - eab_hmac_key: External Account Binding HMAC key"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start acme-proxy"
echo ""
echo "  3. Check status:"
echo "     sudo systemctl status acme-proxy"
echo "     sudo journalctl -u acme-proxy -f"
echo ""
