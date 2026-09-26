#!/data/data/com.termux/files/usr/bin/env bash
#
# PTK installer for Termux.
# Installs runtime dependencies and makes `ptk` runnable.
#
set -euo pipefail

echo "[*] PTK - Pentest Toolkit installer (Termux)"

if command -v pkg >/dev/null 2>&1; then
    echo "[*] Updating packages..."
    pkg update -y || true
    echo "[*] Installing python, dnsutils, whois..."
    pkg install -y python dnsutils whois
else
    echo "[!] 'pkg' not found. This installer targets Termux."
    echo "    On other systems, ensure python3, dig (dnsutils) and whois are installed."
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create a convenience launcher on PATH if possible.
if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ]; then
    LAUNCHER="${PREFIX}/bin/ptk"
    cat > "$LAUNCHER" <<EOF
#!/data/data/com.termux/files/usr/bin/env bash
exec python "${DIR}/ptk.py" "\$@"
EOF
    chmod +x "$LAUNCHER"
    echo "[+] Installed launcher: ${LAUNCHER}"
    echo "[+] Run it with:  ptk"
else
    echo "[*] Run the tool with:  python ${DIR}/ptk.py"
fi

echo "[+] Done."
