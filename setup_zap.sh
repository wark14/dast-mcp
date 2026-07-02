#!/usr/bin/env bash
#
# setup_zap.sh — installs a fully self-contained OWASP ZAP into ./zap/ inside this project.
#
# The ZAP Linux package needs Java 17+, so this script also downloads a portable Temurin
# JRE and drops it in ./zap/jre. Nothing is installed system-wide and no sudo/Java is
# required up front. Idempotent: re-running is a no-op once both are present.
#
set -euo pipefail

ZAP_VERSION="2.16.1"
ZAP_TARBALL="ZAP_${ZAP_VERSION}_Linux.tar.gz"
ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/${ZAP_TARBALL}"
# Adoptium API redirects to the latest Temurin 17 JRE tarball for linux/x64.
JRE_URL="https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jre/hotspot/normal/eclipse"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZAP_DIR="${PROJECT_DIR}/zap"
JRE_DIR="${ZAP_DIR}/jre"

if [ -x "${ZAP_DIR}/zap.sh" ] && [ -x "${JRE_DIR}/bin/java" ]; then
    echo "[setup_zap] ZAP already installed at ${ZAP_DIR}"
    exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${ZAP_DIR}" "${JRE_DIR}"

echo "[setup_zap] Downloading portable Java 17 runtime (Temurin)..."
curl -L --fail -o "${TMP_DIR}/jre.tar.gz" "${JRE_URL}"
echo "[setup_zap] Extracting Java runtime into ${JRE_DIR}..."
tar -xzf "${TMP_DIR}/jre.tar.gz" -C "${JRE_DIR}" --strip-components=1

echo "[setup_zap] Downloading OWASP ZAP ${ZAP_VERSION} (~160MB)..."
curl -L --fail -o "${TMP_DIR}/zap.tar.gz" "${ZAP_URL}"
echo "[setup_zap] Extracting ZAP into ${ZAP_DIR}..."
tar -xzf "${TMP_DIR}/zap.tar.gz" -C "${ZAP_DIR}" --strip-components=1
chmod +x "${ZAP_DIR}/zap.sh" 2>/dev/null || true

if [ -x "${ZAP_DIR}/zap.sh" ] && [ -x "${JRE_DIR}/bin/java" ]; then
    echo "[setup_zap] Success."
    echo "[setup_zap]   ZAP launcher: ${ZAP_DIR}/zap.sh"
    "${JRE_DIR}/bin/java" -version 2>&1 | head -1 | sed 's/^/[setup_zap]   JRE: /'
    echo "[setup_zap] The app auto-starts this ZAP daemon on the first scan."
else
    echo "[setup_zap] ERROR: installation incomplete." >&2
    exit 1
fi
