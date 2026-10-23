#!/bin/bash
cd /mnt/c/Core
bash -n install.sh && echo "SYNTAX OK"
grep -n "7000\|127.0.0.1\|localhost" traffic_tracker.sh
# Репродукция: пустой crontab + set -euo pipefail
TMP=$(mktemp -d)
cat > "$TMP/crontab" << 'EOF'
#!/bin/bash
if [ "$1" = "-l" ]; then echo "no crontab for root" >&2; exit 1; fi
cat > /dev/null
EOF
chmod +x "$TMP/crontab"
PATH="$TMP:$PATH" bash -c '
set -euo pipefail
INSTALL_DIR=/opt/vkturn
warn() { echo "WARN $*"; }
{ { crontab -l 2>/dev/null || true; } | { grep -v tracker.sh || true; }
  echo "* * * * * $INSTALL_DIR/tracker.sh"
  echo "* * * * * sleep 30; $INSTALL_DIR/tracker.sh"
} | crontab - || warn "crontab failed"
echo "REACHED vkturn:// output"
'
echo "--- old line on GitHub-before, for comparison:"
PATH="$TMP:$PATH" bash -c '
set -euo pipefail
(crontab -l 2>/dev/null | grep -v tracker.sh; echo x) | crontab -
echo "REACHED (old)"
'; echo "old exit=$?"
rm -rf "$TMP"
