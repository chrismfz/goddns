#!/bin/sh
# Pins the upgrade branch of the .deb postinst: an ACTIVE goddns-zoned is
# restarted with goddns (both run the same binary), an inactive one is left
# alone, and a fresh install starts nothing. systemctl/getent/... are stubs.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
for c in getent useradd adduser groupadd addgroup usermod chown chmod install mkdir touch cp; do
  printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/$c"; chmod +x "$tmp/bin/$c"
done
cat > "$tmp/bin/systemctl" <<'S'
#!/bin/sh
echo "$*" >> "$LOG"
case "$1 $2 $3" in
  "is-active --quiet goddns-zoned.service") [ "${ZONED_ACTIVE:-0}" = 1 ] ;;
  "is-active --quiet goddns.service") exit 0 ;;
  *) exit 0 ;;
esac
S
chmod +x "$tmp/bin/systemctl"
run() { LOG="$tmp/log.$1"; export LOG; : > "$LOG"; ZONED_ACTIVE=$2 PATH="$tmp/bin:$PATH" sh "$here/packaging/debian/DEBIAN/postinst" configure $3 >/dev/null 2>&1 || true; cat "$LOG"; }
out=$(run up-active 1 2026.11.01)
echo "$out" | grep -q 'restart goddns-zoned.service' || { echo "FAIL: active zoned not restarted on upgrade"; exit 1; }
echo "$out" | grep -q 'restart goddns.service' || { echo "FAIL: goddns not restarted on upgrade"; exit 1; }
out=$(run up-inactive 0 2026.11.01)
echo "$out" | grep -q 'restart goddns-zoned.service' && { echo "FAIL: inactive zoned was started"; exit 1; }
out=$(run fresh 1 "")
echo "$out" | grep -qE 'restart|enable|start ' && { echo "FAIL: fresh install started/enabled something: $out"; exit 1; }
echo "postinst: ok"
