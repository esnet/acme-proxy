#!/bin/sh
#
# Uninstalls acme-proxy and related configuration files on a linux host for a clean start
#
set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/acme-proxy}"
SERVICE_USER="${SERVICE_USER:-acme-proxy}"
SERVICE_GROUP="${SERVICE_GROUP:-acme-proxy}"
SERVICE_FILE="/etc/systemd/system/acme-proxy.service"

echo "Stopping acme-proxy service..."
if systemctl is-active --quiet acme-proxy 2>/dev/null; then
    systemctl stop acme-proxy
fi

echo "Disabling acme-proxy service..."
if systemctl is-enabled --quiet acme-proxy 2>/dev/null; then
    systemctl disable acme-proxy
fi

echo "Removing systemd service file..."
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
fi

echo "Clearing any failed state..."
systemctl reset-failed acme-proxy 2>/dev/null || true

echo "Removing installation directory ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
fi

echo "Removing service user ${SERVICE_USER}..."
if id "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}"
fi

if [ "${SERVICE_USER}" != "${SERVICE_GROUP}" ]; then
    echo "Removing service group ${SERVICE_GROUP}..."
    if getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        groupdel "${SERVICE_GROUP}"
    fi
fi

echo ""
echo "Uninstallation complete."
echo ""
