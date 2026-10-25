#!/bin/sh
# /opt/zapret2/z2k-dns-redirect.sh — защита открытого DNS: заворот UDP/TCP 53 из
# локальной сети на резолвер роутера.
#
# ЧТО ЛЕЧИМ. Замер 25.10.2026 на линии владельца (ЭР-Телеком): на любой
# незашифрованный DNS-запрос из сети о заблокированном имени к ЛЮБОМУ внешнему
# резолверу (8.8.8.8, 1.1.1.1, 9.9.9.9) коробка провайдера отвечает первой —
# адресом своей заглушки, за 0,4 мс, с TTL 127 и постоянным IP ID. Для части
# имён настоящий ответ резолвера она ещё и гасит, подкладывая второй фейк,
# NXDOMAIN. По TCP к тому же резолверу всё честно, через DoT/DoH — тоже.
#
# Устройства, которые спрашивают DNS у роутера, этого не видят: резолвер
# Keenetic ходит к апстриму как настроено (у многих — DoT/DoH). Страдают те,
# кто ходит мимо роутера напрямую к внешнему серверу обычным UDP: Android и
# телевизоры с зашитым 8.8.8.8, приставки, часть приложений. Их запросы идут
# транзитом через роутер — и здесь их можно развернуть.
#
# ЧТО ДЕЛАЕМ. nat PREROUTING: пакет на порт 53 из LAN-подсети на адрес ВНЕ
# LAN-подсетей → REDIRECT на порт 53 роутера (резолвер слушает 0.0.0.0:53).
# Клиент по-прежнему видит ответ «от 8.8.8.8» — его де-NAT'ит conntrack.
# Проверено с клиента в LAN: instagram/torproject/meduza получают настоящие
# адреса вместо заглушки. Два правила (udp, tcp) и один ipset LAN-подсетей;
# ipset переживает регены NDM, правила возвращает хук 89-z2k-dns-redirect.sh.
#
# ЧЕГО НЕ ДЕЛАЕМ. Не трогаем запросы к серверам внутри LAN (свой Pi-hole,
# AdGuard на отдельной машине — dst в ipset, правило не срабатывает), не
# трогаем собственные запросы роутера (OUTPUT) — иначе апстрим его же
# резолвера зациклится. Если на 53-м порту роутера никто не слушает, правила
# не ставим: заворот в пустоту отключил бы DNS всей сети. IPv6 в этой версии
# не заворачиваем.
#
# Один источник правды: эти функции зовут S99zapret2 (start/stop), хук NDM и
# тумблер панели (toggle_dns_redirect).

Z2K_DNS_SET="z2k_lan4"
Z2K_DNS_PORT=53
Z2K_DNS_CONFIG="${Z2K_DNS_CONFIG:-/opt/zapret2/config}"

# xtables-lock-safe iptables (-w), откат на голый вызов у старых сборок.
_z2k_dns_ipt() { iptables -w "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }

# Подсети LAN: маршруты scope link на мостах br* (домашний и гостевые сегменты).
z2k_dns_lan_nets() {
    ip -4 route show 2>/dev/null | awk '$1 ~ /\// && / dev br[0-9]+ / && / scope link/ { print $1 }'
}

z2k_dns_ensure_ipset() {
    ipset create "$Z2K_DNS_SET" hash:net -exist 2>/dev/null || return 1
    _n=0
    for _net in $(z2k_dns_lan_nets); do
        ipset add "$Z2K_DNS_SET" "$_net" -exist 2>/dev/null && _n=$((_n + 1))
    done
    # Петля — не LAN, но и не «внешний мир»: сюда заворачивать нечего.
    ipset add "$Z2K_DNS_SET" 127.0.0.0/8 -exist 2>/dev/null
    [ "$_n" -gt 0 ]
}

# Флаг включения: ENABLED=1 и Z2K_DNS_REDIRECT не 0 (по умолчанию включено).
z2k_dns_enabled() {
    [ -f "$Z2K_DNS_CONFIG" ] || return 1
    grep -q '^ENABLED=1' "$Z2K_DNS_CONFIG" 2>/dev/null || return 1
    _v=$(awk -F= '/^Z2K_DNS_REDIRECT=/ { gsub(/[" ]/, "", $2); print $2; exit }' "$Z2K_DNS_CONFIG" 2>/dev/null)
    [ "$_v" != "0" ]
}

# Резолвер роутера слушает 53-й порт? Без него заворот = DNS всей сети в пустоту.
z2k_dns_resolver_listening() {
    netstat -lun 2>/dev/null | awk '{ print $4 }' | grep -q -E '(^|:)53$'
}

_z2k_dns_rule() { # $1 = -C|-I|-D  $2 = udp|tcp
    if [ "$1" = "-I" ]; then
        _z2k_dns_ipt -t nat -I PREROUTING 1 -p "$2" --dport "$Z2K_DNS_PORT" -m set --match-set "$Z2K_DNS_SET" src -m set ! --match-set "$Z2K_DNS_SET" dst -j REDIRECT --to-ports "$Z2K_DNS_PORT"
    else
        _z2k_dns_ipt -t nat "$1" PREROUTING -p "$2" --dport "$Z2K_DNS_PORT" -m set --match-set "$Z2K_DNS_SET" src -m set ! --match-set "$Z2K_DNS_SET" dst -j REDIRECT --to-ports "$Z2K_DNS_PORT"
    fi
}

z2k_dns_rule_present() { _z2k_dns_rule -C "$1"; }

# Поставить оба правила с проверкой и повтором (гонка с NDM за xtables-lock).
# 0 — оба правила подтверждены.
z2k_dns_ensure_rules() {
    z2k_dns_resolver_listening || return 1
    z2k_dns_ensure_ipset || return 1
    _retry=0
    while [ "$_retry" -lt 3 ]; do
        z2k_dns_rule_present udp || _z2k_dns_rule -I udp
        z2k_dns_rule_present tcp || _z2k_dns_rule -I tcp
        if z2k_dns_rule_present udp && z2k_dns_rule_present tcp; then return 0; fi
        _retry=$((_retry + 1))
        [ "$_retry" -lt 3 ] && sleep 1
    done
    return 1
}

# Снять правила (все копии). ipset оставляем: дёшев и нужен на следующем старте.
z2k_dns_remove_rules() {
    for _p in udp tcp; do
        _guard=0
        while z2k_dns_rule_present "$_p"; do
            _z2k_dns_rule -D "$_p" || break
            _guard=$((_guard + 1)); [ "$_guard" -gt 20 ] && break
        done
    done
    return 0
}

# Движок z2k запущен? Хук NDM не возвращает правила остановленной службе.
z2k_dns_service_running() {
    for _pf in "${PIDDIR:-/var/run}"/nfqws2_*.pid; do
        [ -f "$_pf" ] || continue
        _pid=$(cat "$_pf" 2>/dev/null)
        case "$_pid" in ''|*[!0-9]*) continue ;; esac
        kill -0 "$_pid" 2>/dev/null && return 0
    done
    return 1
}
