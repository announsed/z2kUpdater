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
# ЕСЛИ РЕЗОЛВЕР РОУТЕРА УМЕР. Заворот делает резолвер роутера единственным для
# всей сети: умри он — без имён останутся и те, у кого прописан свой сервер.
# 25.10.2026 так и было: провайдер начал рвать DoH-апстрим роутера, резолвер
# продолжал слушать 53-й порт, но не отвечал. Поэтому раз в минуту планировщик
# зовёт z2k_dns_watch: короткий запрос по TCP к резолверу роутера, не дольше
# 4 с. Два провала подряд — правила снимаются и стоит отметка «приостановлено»,
# устройства ходят к своим серверам напрямую, как без защиты. Два ответа подряд —
# отметка снимается, правила возвращаются. Пока отметка стоит, правила не
# ставят ни S99, ни хук NDM.
#
# Один источник правды: эти функции зовут S99zapret2 (start/stop), хук NDM,
# планировщик (z2k_dns_watch) и тумблер панели (toggle_dns_redirect).

Z2K_DNS_SET="z2k_lan4"
Z2K_DNS_PORT=53
Z2K_DNS_CONFIG="${Z2K_DNS_CONFIG:-/opt/zapret2/config}"
# tmpfs: после перезагрузки отметка и счётчики начинаются с нуля.
Z2K_DNS_STATE_DIR="${Z2K_DNS_STATE_DIR:-/tmp}"
Z2K_DNS_HC_SERVER="${Z2K_DNS_HC_SERVER:-127.0.0.1}"
Z2K_DNS_LOG="${Z2K_DNS_LOG:-/tmp/z2k-log/dns-redirect.log}"

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

# Заворот приостановлен проверкой живости (см. z2k_dns_watch)?
z2k_dns_paused() { [ -f "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.down" ]; }

# Поставить оба правила с проверкой и повтором (гонка с NDM за xtables-lock).
# 0 — оба правила подтверждены.
z2k_dns_ensure_rules() {
    z2k_dns_paused && return 1
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

# Отвечает ли резолвер: запрос несуществующего имени по TCP, не дольше 4 с.
#
# Слушать порт мало — 25.10.2026 резолвер слушал, а апстрим был мёртв. Имя
# случайное, чтобы ответ не взялся из кэша и проверил апстрим. Живой ответ —
# NOERROR или NXDOMAIN с нашим идентификатором; SERVFAIL, тишина и мусор —
# провал. По TCP, а не по UDP: nc из BusyBox умеет только TCP, а резолвер
# Keenetic слушает 53-й порт и по TCP. Своего таймаута у nc нет, поэтому ждём
# ответ сами и гасим nc по сроку.
z2k_dns_resolver_answers() {
    _hs=${1:-$Z2K_DNS_HC_SERVER}
    _hf="$Z2K_DNS_STATE_DIR/z2k-dns-hc.$$"
    _hr=$(awk 'BEGIN { srand(); printf "%06d", int(rand() * 1000000) }')
    # длина 41 = заголовок 12 + имя z2khcNNNNNN.example.com (25) + тип и класс 4;
    # идентификатор 0x5A6B
    { printf '\000\051\132\153\001\000\000\001\000\000\000\000\000\000'
      printf '\013z2khc%s\007example\003com\000\000\001\000\001' "$_hr"
      sleep 4; } | nc "$_hs" 53 > "$_hf" 2>/dev/null &
    _hp=$!
    _hw=0
    while [ "$_hw" -lt 4 ]; do
        [ "$(wc -c < "$_hf" 2>/dev/null || echo 0)" -ge 6 ] && break
        sleep 1; _hw=$((_hw + 1))
    done
    kill "$_hp" 2>/dev/null
    _hid=$(dd if="$_hf" bs=1 skip=2 count=2 2>/dev/null | od -b | awk 'NR == 1 { print $2 $3 }')
    _hrc=$(dd if="$_hf" bs=1 skip=5 count=1 2>/dev/null | od -b | awk 'NR == 1 && NF > 1 { print $2 }')
    rm -f "$_hf"
    [ "$_hid" = "132153" ] || return 1
    case "$_hrc" in ''|*[!0-7]*) return 1 ;; esac
    _hcode=$(( 0$_hrc & 15 ))
    [ "$_hcode" = 0 ] || [ "$_hcode" = 3 ]
}

_z2k_dns_log() {
    mkdir -p "${Z2K_DNS_LOG%/*}" 2>/dev/null
    printf '%s %s\n' "$(date '+%F %T' 2>/dev/null)" "$1" >> "$Z2K_DNS_LOG" 2>/dev/null
    # журнал в tmpfs, но не безразмерный
    if [ "$(wc -l < "$Z2K_DNS_LOG" 2>/dev/null || echo 0)" -gt 200 ]; then
        tail -n 100 "$Z2K_DNS_LOG" > "$Z2K_DNS_LOG.new" 2>/dev/null && mv -f "$Z2K_DNS_LOG.new" "$Z2K_DNS_LOG"
    fi
}

# Сбросить отметку и счётчики (тумблер выключили — начинать с чистого листа).
z2k_dns_reset_health() {
    rm -f "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.down" "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.hc" 2>/dev/null
}

# Раз в минуту из планировщика. Два провала подряд — снять правила и поставить
# отметку; два ответа подряд — снять отметку и вернуть правила. Пока резолвер
# жив, заодно возвращает правила, если их снёс реген NDM, а хук не успел.
z2k_dns_watch() {
    if ! z2k_dns_enabled || ! z2k_dns_service_running; then
        rm -f "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.hc" 2>/dev/null
        return 0
    fi
    _wok=0; _wfail=0
    [ -f "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.hc" ] && read -r _wok _wfail < "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.hc"
    case "$_wok" in ''|*[!0-9]*) _wok=0 ;; esac
    case "$_wfail" in ''|*[!0-9]*) _wfail=0 ;; esac
    if z2k_dns_resolver_answers; then
        _wok=$((_wok + 1)); _wfail=0
    else
        _wfail=$((_wfail + 1)); _wok=0
    fi
    printf '%s %s\n' "$_wok" "$_wfail" > "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.hc" 2>/dev/null
    if z2k_dns_paused; then
        if [ "$_wok" -ge 2 ]; then
            rm -f "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.down" 2>/dev/null
            if z2k_dns_ensure_rules; then
                _z2k_dns_log "резолвер роутера снова отвечает — заворот DNS возвращён"
            fi
        fi
    elif [ "$_wfail" -ge 2 ]; then
        : > "$Z2K_DNS_STATE_DIR/z2k-dns-redirect.down" 2>/dev/null
        z2k_dns_remove_rules
        _z2k_dns_log "резолвер роутера не отвечает 2 проверки подряд — заворот DNS приостановлен"
    elif [ "$_wok" -ge 1 ]; then
        z2k_dns_ensure_rules >/dev/null 2>&1
    fi
    return 0
}
