#!/bin/sh
# tests/test_warp_trust_roots.sh — движок WARP видит наши корни TLS.
#
# ЧТО БЫЛО. Диагностика 2026-10-18: регистрация у Cloudflare двое суток
# падала одинаково — и напрямую, и через релей:
#
#   tls: failed to verify certificate: x509: certificate signed by unknown authority
#
# Сертификат api.cloudflareclient.com выпущен по цепочке YE1 → Root YE →
# ISRG Root X2, а в прошивке роутера X2 нет. Корни мы возим сами
# (files/etc/z2k-roots.pem, ставится каждой установке), но SSL_CERT_FILE
# экспортировал только init туннеля Телеграма — движок WARP их не видел.
#
# Проверяем три вещи:
#   1. обе двери к движку (z2k-warp.sh и S51z2k-warp) отдают ему наш файл;
#   2. без файла переменная НЕ ставится (пустой SSL_CERT_FILE обнулил бы пул
#      там, где сейчас всё работает);
#   3. в отгружаемом наборе действительно есть ISRG Root X2.
#
# POSIX sh.
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '[FAIL] %s (want=%s got=%s)\n' "$1" "$2" "$3"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W="$ROOT/files/z2k-warp.sh"
INIT="$ROOT/files/init.d/S51z2k-warp"
PEM="$ROOT/files/etc/z2k-roots.pem"
SB=$(mktemp -d) || exit 1
trap 'rm -rf "$SB"' EXIT INT TERM

mkdir -p "$SB/stub" "$SB/zd/etc" "$SB/log"
for c in ipset ip iptables ip6tables; do
    printf '#!/bin/sh\nexit 0\n' > "$SB/stub/$c"; chmod +x "$SB/stub/$c"
done
printf 'GAME_WARP_ENABLED=1\n' > "$SB/zd/config"

# Движок-заглушка записывает, какие корни ему дали, и падает на регистрации —
# этого достаточно, чтобы warp_register дошёл до обеих попыток.
cat > "$SB/warpd" <<'STUB'
#!/bin/sh
printf '%s file=%s\n' "$1" "${SSL_CERT_FILE:-<unset>}" >> "$CALLS"
[ "$1" = "register" ] && exit 1
exit 0
STUB
chmod +x "$SB/warpd"
printf '#!/bin/sh\n[ "$1" = "status" ] && exit 1\nexit 0\n' > "$SB/init"; chmod +x "$SB/init"

run_selfheal() {
    CALLS="$SB/calls" \
    Z2K_STUB_PATH="$SB/stub" \
    ZAPRET2_DIR="$SB/zd" CONFIG_FILE="$SB/zd/config" \
    WARP_BIN="$SB/warpd" WARP_INIT="$SB/init" \
    WARP_DEVICE="$SB/device.json" WARP_STATUS="$SB/status.json" \
    WARP_LOG="$SB/log/warpd.log" WARP_REG_STAMP="$SB/reg.stamp" \
    WARP_LISTS_DIR="$SB/zd/lists/warp" \
    sh "$W" selfheal >/dev/null 2>&1
}

# --- 1. z2k-warp.sh: регистрация видит наш файл корней -----------------------
cp "$PEM" "$SB/zd/etc/z2k-roots.pem"
: > "$SB/calls"; rm -f "$SB/reg.stamp" "$SB/device.json"
run_selfheal
assert_eq "регистрация напрямую получает наши корни" \
    "register file=$SB/zd/etc/z2k-roots.pem" "$(grep '^register' "$SB/calls" | head -1)"
assert_eq "регистрация через релей получает наши корни" \
    "register file=$SB/zd/etc/z2k-roots.pem" "$(grep '^register' "$SB/calls" | sed -n 2p)"

# --- 2. Нет файла — переменной нет -------------------------------------------
rm -f "$SB/zd/etc/z2k-roots.pem"
: > "$SB/calls"; rm -f "$SB/reg.stamp"
run_selfheal
assert_eq "без файла корней SSL_CERT_FILE не ставится" \
    "register file=<unset>" "$(grep '^register' "$SB/calls" | head -1)"

# --- 3. S51z2k-warp: демон, поднятый мимо z2k-warp.sh, тоже видит корни -----
# Движок поднимают и напрямую: Entware при загрузке, хук NDM, selfheal.
cat > "$SB/warpd-run" <<'STUB'
#!/bin/sh
printf 'run file=%s\n' "${SSL_CERT_FILE:-<unset>}" >> "$CALLS"
exit 0
STUB
chmod +x "$SB/warpd-run"
run_init() {
    CALLS="$SB/calls" Z2K_STUB_PATH="$SB/stub" ZAPRET2_DIR="$SB/zd" \
    BIN="$SB/warpd-run" PIDFILE="$SB/warpd.pid" \
    sh "$INIT" start >/dev/null 2>&1
}
cp "$PEM" "$SB/zd/etc/z2k-roots.pem"
: > "$SB/calls"; run_init
assert_eq "init отдаёт демону наши корни" "run file=$SB/zd/etc/z2k-roots.pem" "$(grep '^run' "$SB/calls" | head -1)"
rm -f "$SB/zd/etc/z2k-roots.pem"
: > "$SB/calls"; run_init
assert_eq "init без файла корней переменную не ставит" "run file=<unset>" "$(grep '^run' "$SB/calls" | head -1)"

# Каталоги прошивки и Entware не теряются: SSL_CERT_FILE в Go заменяет только
# файл, каталоги обязаны быть перечислены явно в обоих местах.
for f in "$W" "$INIT"; do
    case "$(cat "$f")" in
        *"/etc/ssl/certs /opt/etc/ssl/certs"*) ok "$(basename "$f"): каталоги прошивки и Entware в SSL_CERT_DIR" ;;
        *) no "$(basename "$f"): каталоги прошивки и Entware в SSL_CERT_DIR" "оба каталога" "нет" ;;
    esac
done

# --- 4. В нашем наборе есть ISRG Root X2 -------------------------------------
# Именно им замыкается цепочка api.cloudflareclient.com. Отпечаток — из шапки
# файла, сверенный с letsencrypt.org при его создании.
X2=69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470
if command -v openssl >/dev/null 2>&1; then
    got=$(awk -v d="$SB" '/BEGIN CERT/{n++} {print > (d "/c" n ".pem")}' "$PEM"
          for c in "$SB"/c[0-9]*.pem; do
              openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null
          done | tr -d ':' | sed 's/.*=//' | grep -x "$X2")
    assert_eq "в z2k-roots.pem есть ISRG Root X2 (по отпечатку)" "$X2" "$got"
else
    ok "openssl нет — сверка отпечатка X2 пропущена"
fi

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
