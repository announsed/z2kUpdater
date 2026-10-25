#!/bin/sh
# Z2K_STUB_PATH — только для тестов: каталог со стабами iptables/ipset/ip/netstat
# встаёт перед системным PATH. В проде переменной нет.
export PATH="${Z2K_STUB_PATH:+$Z2K_STUB_PATH:}/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/sbin:/usr/sbin:/bin:/usr/bin"

# /opt/etc/ndm/netfilter.d/89-z2k-dns-redirect.sh
#
# NDM сносит чужие правила iptables на каждом регене netfilter (ребут, флап WAN,
# DHCP, hotplug). Этот хук возвращает заворот открытого DNS из LAN на резолвер
# роутера — ровно теми же функциями, что S99zapret2 и панель
# (/opt/zapret2/z2k-dns-redirect.sh), чтобы форма правил не разъезжалась.
# Только пока защита включена и движок z2k запущен: остановленной службе
# правила не возвращаем.

[ "$type" = "ip6tables" ] && exit 0
[ "$table" = "nat" ] || exit 0

LIB="${Z2K_DNS_REDIRECT_LIB:-/opt/zapret2/z2k-dns-redirect.sh}"
[ -r "$LIB" ] || exit 0
. "$LIB"

z2k_dns_enabled || exit 0
z2k_dns_service_running || exit 0
z2k_dns_ensure_rules
exit 0
