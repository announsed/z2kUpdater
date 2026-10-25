#!/bin/sh
# tests/test_dns_redirect.sh — защита открытого DNS: библиотека правил и хук NDM.
#
# Библиотека /opt/zapret2/z2k-dns-redirect.sh ставит два правила nat PREROUTING
# (udp/tcp :53, источник в ipset LAN-подсетей, назначение вне его → REDIRECT
# :53) и один ipset. Проверяем форму правил, идемпотентность, снятие, отказ без
# резолвера на :53 и без LAN-подсетей, чтение флага, и хук: только nat, только
# при включённом флаге и живом движке. Стабы iptables/ipset/ip/netstat пишут
# argv в журнал. POSIX sh.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIB="$ROOT/files/z2k-dns-redirect.sh"
HOOK="$ROOT/files/ndm/89-z2k-dns-redirect.sh"
SB=$(mktemp -d "${TMPDIR:-/tmp}/dnsredir.XXXXXX") || exit 1
trap 'rm -rf "$SB"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '[FAIL] %s (want=%s got=%s)\n' "$1" "$2" "$3"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }

mkdir -p "$SB/bin" "$SB/run"
# iptables: -C отвечает по файлу present (протоколы уже стоящих правил), -I/-D правят его
cat > "$SB/bin/iptables" <<EOF
#!/bin/sh
echo "\$*" >> "$SB/ipt.log"
args="\$*"; proto=\$(printf '%s' "\$args" | sed -n 's/.*-p \([a-z]*\) .*/\1/p')
case "\$args" in
  *" -C "*) grep -qx "\$proto" "$SB/present" 2>/dev/null ;;
  *" -I "*) echo "\$proto" >> "$SB/present" ;;
  *" -D "*) grep -vx "\$proto" "$SB/present" > "$SB/present.new" 2>/dev/null; mv "$SB/present.new" "$SB/present" ;;
  *) exit 0 ;;
esac
EOF
printf '#!/bin/sh\necho "$*" >> "%s/ipset.log"; exit 0\n' "$SB" > "$SB/bin/ipset"
printf '#!/bin/sh\ncat "%s/routes"\n' "$SB" > "$SB/bin/ip"
printf '#!/bin/sh\ncat "%s/netstat"\n' "$SB" > "$SB/bin/netstat"
chmod +x "$SB/bin/"*
PATH="$SB/bin:$PATH"; export PATH
printf '192.168.1.0/24 dev br0 scope link  src 192.168.1.1\n10.1.30.0/24 dev br1 scope link  src 10.1.30.1\n0.0.0.0/0 via 1.2.3.4 dev ppp0\n' > "$SB/routes"
printf 'udp        0      0 0.0.0.0:53              0.0.0.0:*\nudp        0      0 192.168.1.1:67          0.0.0.0:*\n' > "$SB/netstat"
printf 'ENABLED=1\n' > "$SB/config"
Z2K_DNS_CONFIG="$SB/config"; PIDDIR="$SB/run"; export Z2K_DNS_CONFIG PIDDIR
reset() { : > "$SB/present"; : > "$SB/ipt.log"; : > "$SB/ipset.log"; }

. "$LIB"

# --- подсети и ipset
assert_eq "LAN-подсети: оба моста, без маршрута по умолчанию" "192.168.1.0/24 10.1.30.0/24" "$(z2k_dns_lan_nets | tr '\n' ' ' | sed 's/ $//')"
reset; z2k_dns_ensure_ipset
assert_eq "ipset создан hash:net" "1" "$(grep -c 'create z2k_lan4 hash:net -exist' "$SB/ipset.log")"
assert_eq "ipset: обе подсети и петля" "3" "$(grep -c '^add z2k_lan4 ' "$SB/ipset.log")"

# --- правила
reset; z2k_dns_ensure_rules; rc=$?
assert_eq "ensure: успех" "0" "$rc"
assert_eq "ensure: два правила вставлены (udp, tcp)" "2" "$(grep -c -- '-I PREROUTING 1 -p' "$SB/ipt.log")"
assert_eq "ensure: форма правила — источник в LAN, назначение вне LAN, REDIRECT :53" "1" \
    "$(grep -c -- '-t nat -I PREROUTING 1 -p udp --dport 53 -m set --match-set z2k_lan4 src -m set ! --match-set z2k_lan4 dst -j REDIRECT --to-ports 53' "$SB/ipt.log")"
assert_eq "ensure: правила только в nat PREROUTING, не в OUTPUT" "0" "$(grep -c ' OUTPUT ' "$SB/ipt.log")"
: > "$SB/ipt.log"; z2k_dns_ensure_rules
assert_eq "ensure повторно: правила уже стоят — вставок нет" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"
assert_eq "present: оба" "1" "$(z2k_dns_rule_present udp && z2k_dns_rule_present tcp && echo 1 || echo 0)"
: > "$SB/ipt.log"; z2k_dns_remove_rules
assert_eq "remove: оба правила сняты" "2" "$(grep -c -- ' -D PREROUTING ' "$SB/ipt.log")"
assert_eq "remove: ничего не осталось" "0" "$(grep -c . "$SB/present")"
printf 'udp\nudp\ntcp\n' > "$SB/present"; : > "$SB/ipt.log"; z2k_dns_remove_rules
assert_eq "remove: дубликаты сняты до нуля" "0" "$(grep -c . "$SB/present")"

# --- предохранители
reset; : > "$SB/netstat"
z2k_dns_ensure_rules; rc=$?
assert_eq "нет слушателя на :53 -> правила не ставим" "1" "$rc"
assert_eq "нет слушателя: вставок нет" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"
printf 'udp        0      0 0.0.0.0:53              0.0.0.0:*\n' > "$SB/netstat"
reset; printf '0.0.0.0/0 via 1.2.3.4 dev ppp0\n' > "$SB/routes"
z2k_dns_ensure_rules; rc=$?
assert_eq "нет LAN-подсетей -> правила не ставим" "1" "$rc"
printf '192.168.1.0/24 dev br0 scope link  src 192.168.1.1\n' > "$SB/routes"

# --- флаг
assert_eq "флаг: по умолчанию включено" "0" "$(z2k_dns_enabled; echo $?)"
printf 'ENABLED=1\nZ2K_DNS_REDIRECT=0\n' > "$SB/config"
assert_eq "флаг: Z2K_DNS_REDIRECT=0 выключает" "1" "$(z2k_dns_enabled; echo $?)"
printf 'ENABLED=0\nZ2K_DNS_REDIRECT=1\n' > "$SB/config"
assert_eq "флаг: ENABLED=0 выключает" "1" "$(z2k_dns_enabled; echo $?)"
printf 'ENABLED=1\nZ2K_DNS_REDIRECT="1"\n' > "$SB/config"
assert_eq "флаг: значение в кавычках читается" "0" "$(z2k_dns_enabled; echo $?)"

# --- хук NDM
runhook() { # $1=type $2=table
    : > "$SB/ipt.log"
    type="$1" table="$2" Z2K_DNS_REDIRECT_LIB="$LIB" Z2K_DNS_CONFIG="$SB/config" PIDDIR="$SB/run" Z2K_STUB_PATH="$SB/bin" sh "$HOOK" >/dev/null 2>&1
}
printf 'ENABLED=1\n' > "$SB/config"; : > "$SB/present"
echo $$ > "$SB/run/nfqws2_1.pid"
runhook iptables nat
assert_eq "хук: nat + включено + движок жив -> правила поставлены" "2" "$(grep -c -- ' -I PREROUTING ' "$SB/ipt.log")"
: > "$SB/present"; runhook iptables mangle
assert_eq "хук: таблица mangle -> ничего" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"
runhook ip6tables nat
assert_eq "хук: ip6tables -> ничего" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"
printf 'ENABLED=1\nZ2K_DNS_REDIRECT=0\n' > "$SB/config"; runhook iptables nat
assert_eq "хук: флаг выключен -> ничего" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"
printf 'ENABLED=1\n' > "$SB/config"; echo 4194300 > "$SB/run/nfqws2_1.pid"; runhook iptables nat
assert_eq "хук: движок мёртв -> остановленной службе правила не возвращаем" "0" "$(grep -c -- ' -I ' "$SB/ipt.log")"

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
