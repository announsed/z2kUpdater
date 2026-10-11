#!/bin/sh
# tests/test_opkg_via_vps.sh — наши вызовы opkg качают через curl, а хосты
# *.entware.net — через узел, как GitHub (`curl --resolve <host>:443:<узел>`).
#
# Повод, 11.10.2026, замер на роутере владельца (KN-1811, Entware aarch64):
# bin.entware.net режется по объёму — список пакетов обрывается на 31 КБ из
# 378 КБ, а opkg зовёт busybox wget без таймаута и висит без конца (326 с, пока
# не сняли). Через узел — оба фида за 1 с. Таймаут busybox wget не
# вариант: 1.37.0-6 падает с segfault на ключе -T.
# Поэтому z2k_opkg кладёт впереди PATH свой временный `wget`, который качает
# curl'ом. Что пинится:
#   - разбор аргументов, с которыми opkg зовёт wget (-q, --timeout N, -O файл,
#     --no-check-certificate, -Y on, URL);
#   - *.entware.net идут по https на адрес узла (--resolve, без логинов),
#     прочие хосты — напрямую;
#   - узел не ответил — повтор напрямую;
#   - curl нет или аргументы незнакомые — настоящий wget с исходными аргументами;
#   - временный каталог убирается, глобальный PATH и opkg.conf не трогаются;
#   - все opkg update/install установщиков идут через z2k_opkg.
# POSIX sh.
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$1"; }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1 (want=[$2] got=[$3])"; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/lib/utils.sh" >/dev/null 2>&1
SB=$(mktemp -d) || exit 1
trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/bin" "$SB/real"

# --- стабы -------------------------------------------------------------------
# curl: пишет аргументы в журнал; «узел» (--resolve) падает, если есть $SB/vps.fail;
# прямой путь падает, если есть $SB/direct.fail. Иначе кладёт тело в -o.
cat > "$SB/bin/curl" <<EOF
#!/bin/sh
echo "\$*" >> "$SB/curl.log"
out=""; vps=0
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o) shift; out="\$1" ;;
        --resolve) vps=1; shift ;;
    esac
    shift
done
if [ "\$vps" = 1 ]; then [ -f "$SB/vps.fail" ] && exit 7; else [ -f "$SB/direct.fail" ] && exit 28; fi
[ -n "\$out" ] && printf 'PKG' > "\$out"
exit 0
EOF
# «настоящий» wget: только журнал аргументов.
cat > "$SB/real/wget" <<EOF
#!/bin/sh
echo "\$*" >> "$SB/realwget.log"
exit 0
EOF
chmod +x "$SB/bin/curl" "$SB/real/wget"

# Шим берём ровно тот, что пишет z2k_opkg.
z2k_opkg_shim > "$SB/shim"; chmod +x "$SB/shim"
SHIMRUN() { env PATH="$SB/bin:/usr/bin:/bin" Z2K_REAL_WGET="$SB/real/wget" Z2K_OPKG_VPS=vps sh "$SB/shim" "$@"; }
reset() { rm -f "$SB"/*.log "$SB/out" "$SB/vps.fail" "$SB/direct.fail"; }

# --- 1. entware.net через узел ----------------------------------------------
reset; SHIMRUN -q --timeout 30 -O "$SB/out" http://bin.entware.net/aarch64-k3.10/Packages.gz; rc=$?
eq "entware: rc 0" "0" "$rc"
eq "entware: файл скачан" "PKG" "$(cat "$SB/out" 2>/dev/null)"
eq "entware: один вызов curl, на адрес узла" "1" "$(grep -c -- '--resolve bin.entware.net:443:vps' "$SB/curl.log")"
eq "entware: по https, тот же путь" "1" "$(grep -c -- ' https://bin.entware.net/aarch64-k3.10/Packages.gz$' "$SB/curl.log")"
eq "entware: никаких прокси и логинов" "0" "$(grep -cE -- '--proxy|@' "$SB/curl.log")"
eq "entware: настоящий wget не звали" "0" "$(cat "$SB/realwget.log" 2>/dev/null | wc -l | tr -d ' ')"
reset; SHIMRUN -q -O "$SB/out" https://mirror.ENTWARE.net/x.ipk
eq "любой поддомен entware.net и регистр — через узел" "1" "$(grep -- '--resolve mirror.entware.net:443:vps ' "$SB/curl.log" | grep -c -- ' https://mirror.entware.net/x.ipk$')"

# --- 2. прочие хосты напрямую ------------------------------------------------
reset; SHIMRUN -q -O "$SB/out" https://mirrors.bfsu.edu.cn/entware/aarch64-k3.10/Packages.gz
eq "чужой хост: не через узел" "0" "$(grep -c -- '--resolve' "$SB/curl.log")"
eq "чужой хост: скачан" "PKG" "$(cat "$SB/out" 2>/dev/null)"
reset; SHIMRUN -q -O "$SB/out" http://notentware.net.evil.com/x
eq "entware.net в середине имени — не наш хост" "0" "$(grep -c -- '--resolve' "$SB/curl.log")"

# --- 3. узел не ответил — напрямую -------------------------------------------
reset; touch "$SB/vps.fail"; SHIMRUN -q -O "$SB/out" http://bin.entware.net/x; rc=$?
eq "узел упал: rc 0 после прямого повтора" "0" "$rc"
eq "узел упал: два вызова curl" "2" "$(wc -l < "$SB/curl.log" | tr -d ' ')"
eq "узел упал: второй вызов напрямую, исходный адрес" "1" "$(sed -n 2p "$SB/curl.log" | grep -v -- '--resolve' | grep -c -- ' http://bin.entware.net/x$')"
reset; touch "$SB/vps.fail" "$SB/direct.fail"; SHIMRUN -q -O "$SB/out" http://bin.entware.net/x; rc=$?
eq "оба пути упали: ненулевой код для opkg" "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

# --- 4. ключи opkg ------------------------------------------------------------
reset; SHIMRUN -q --no-check-certificate --timeout 7 -Y on -O "$SB/out" http://bin.entware.net/x
eq "--no-check-certificate превращается в -k" "1" "$(grep -c -- ' -k ' "$SB/curl.log")"
eq "--timeout 7 становится таймаутом соединения" "1" "$(grep -c -- '--connect-timeout 7 ' "$SB/curl.log")"
eq "застрявшая загрузка обрывается по скорости" "1" "$(grep -c -- '--speed-limit 1024 --speed-time 30' "$SB/curl.log")"

# --- 5. отступление на настоящий wget ----------------------------------------
# Без curl: PATH, где есть только то, что нужно самому шиму до проверки curl.
mkdir -p "$SB/nocurl"; ln -sf "$(command -v sh)" "$SB/nocurl/sh"
reset; env PATH="$SB/nocurl" Z2K_REAL_WGET="$SB/real/wget" "$SB/nocurl/sh" "$SB/shim" -q -O "$SB/out" http://bin.entware.net/x
eq "нет curl: исходные аргументы ушли настоящему wget" "-q -O $SB/out http://bin.entware.net/x" "$(cat "$SB/realwget.log" 2>/dev/null)"
reset; SHIMRUN --post-data=x -O "$SB/out" http://bin.entware.net/x
eq "незнакомый ключ: настоящий wget с исходными аргументами" "--post-data=x -O $SB/out http://bin.entware.net/x" "$(cat "$SB/realwget.log" 2>/dev/null)"
eq "незнакомый ключ: curl не звали" "0" "$(cat "$SB/curl.log" 2>/dev/null | wc -l | tr -d ' ')"

# --- 6. z2k_opkg: opkg видит наш wget, следов не остаётся ---------------------
# Стаб opkg зовёт `wget` так же, как настоящий: из PATH.
cat > "$SB/bin/opkg" <<EOF
#!/bin/sh
echo "opkg \$*" >> "$SB/opkg.log"
wget -q -O "$SB/out" http://bin.entware.net/aarch64-k3.10/Packages.gz
EOF
chmod +x "$SB/bin/opkg"
ln -sf "$SB/real/wget" "$SB/bin/wget"
reset; _before=$(ls -d /tmp/z2k-opkg.* 2>/dev/null | wc -l | tr -d ' ')
_p="$PATH"; PATH="$SB/bin:$PATH" Z2K_OPKG_VPS=vps
z2k_opkg update; rc=$?
PATH="$_p"
eq "z2k_opkg: rc opkg" "0" "$rc"
eq "z2k_opkg: opkg получил аргументы" "opkg update" "$(cat "$SB/opkg.log" 2>/dev/null)"
eq "z2k_opkg: wget внутри opkg — наш, через узел" "1" "$(grep -c -- '--resolve bin.entware.net:443:vps' "$SB/curl.log" 2>/dev/null)"
eq "z2k_opkg: настоящий wget не звали" "0" "$(cat "$SB/realwget.log" 2>/dev/null | wc -l | tr -d ' ')"
eq "z2k_opkg: временный каталог убран" "$_before" "$(ls -d /tmp/z2k-opkg.* 2>/dev/null | wc -l | tr -d ' ')"
eq "z2k_opkg: PATH вызывающего не изменился" "$_p" "$PATH"

# --- 6б. обёртка панели: utils.sh в отдельном sh, под set -eu ------------------
# Установщик панели utils.sh не подключает; его z2k_opkg обязан дойти до того же
# шима. Берём функцию как есть из webpanel/install.sh и гоняем под set -eu.
awk '/^z2k_opkg\(\) \{/,/^\}/' "$ROOT/webpanel/install.sh" > "$SB/panel_fn.sh"
reset
env PATH="$SB/bin:$PATH" SRC_DIR="$ROOT/webpanel" Z2K_OPKG_VPS=vps \
    sh -c 'set -eu; . "$1"; z2k_opkg install lighttpd' sh "$SB/panel_fn.sh"; rc=$?
eq "панель: rc opkg" "0" "$rc"
eq "панель: opkg получил аргументы" "opkg install lighttpd" "$(cat "$SB/opkg.log" 2>/dev/null)"
eq "панель: wget внутри opkg — наш, через узел" "1" "$(grep -c -- '--resolve bin.entware.net:443:vps' "$SB/curl.log" 2>/dev/null)"
reset
env PATH="$SB/bin:$PATH" SRC_DIR="$SB/nowhere" \
    sh -c 'set -eu; . "$1"; z2k_opkg update' sh "$SB/panel_fn.sh" 2>/dev/null
eq "панель без utils.sh: обычный opkg" "opkg update" "$(cat "$SB/opkg.log" 2>/dev/null | head -1)"

# --- 7. все opkg update/install установщиков идут через z2k_opkg --------------
# Справки в тексте (printf/echo/print_*) не в счёт; z2k.sh — загрузчик до
# utils.sh, и там curl ещё нет, шиму нечем качать.
# Тела heredoc (тексты подсказок для человека) не код — выкидываем их.
_code() {
    awk -v f="$1" '
        tag != "" { t = $0; sub(/^\t+/, "", t); if (t == tag) tag = ""; next }
        { print f ":" NR ":" $0 }
        match($0, /<<-?[ \t]*["'\'']?[A-Za-z_]+/) {
            tag = substr($0, RSTART, RLENGTH); sub(/^<<-?[ \t]*["'\'']?/, "", tag)
        }' "$1"
}
_raw=$({ _code "$ROOT/lib/install.sh"; _code "$ROOT/webpanel/install.sh"; } \
    | grep -E ':[0-9]+:.*(^|[^a-z_/.-])opkg +(-[^ ]+ +)*(update|install)([^a-z-]|$)' \
    | grep -vE ':[0-9]+:[[:space:]]*(#|printf|echo|print_[a-z]+)|grep |z2k_opkg|"[^"]*opkg +(update|install)[^"]*"')
eq "в установщиках нет прямых opkg update/install" "" "$_raw"

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
