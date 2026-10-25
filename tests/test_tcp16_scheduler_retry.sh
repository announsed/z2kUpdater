#!/bin/sh
# tests/test_tcp16_scheduler_retry.sh — планировщик и проба обрыва на 16 КБ.
#
# Ревью 25.10.2026, два дефекта:
#   * init сравнивает отметку планировщика с БОЛЬШИМ из времён двух файлов
#     (сам планировщик и проба), а планировщик писал туда только своё время:
#     выпуск, меняющий одну пробу, заставлял init перезапускать планировщик
#     при КАЖДОМ старте службы;
#   * повтор пробы шёл, только пока нет флага, а флаг проба ставит в середине
#     работы — оборванный после этого прогон ждал ночи.
# POSIX sh.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCHED="$ROOT/files/z2k-scheduler.sh"
INIT="$ROOT/files/S99zapret2.new"
SB=$(mktemp -d "${TMPDIR:-/tmp}/t16sched.XXXXXX") || exit 1
trap 'rm -rf "$SB"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '[FAIL] %s (want=%s got=%s)\n' "$1" "$2" "$3"; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }

# --- 1. отметка планировщика и ожидание init считаются одинаково -------------
ZAPRET2_DIR="$SB/z2k"; export ZAPRET2_DIR
mkdir -p "$ZAPRET2_DIR"
: > "$ZAPRET2_DIR/z2k-scheduler.sh"
: > "$ZAPRET2_DIR/z2k-tcp16-probe.sh"

# Время файлов задаём ПОРЯДКОМ СОЗДАНИЯ: у touch на BusyBox нет -t, а набор
# переносимости такие вызовы и ловит. Проба новее планировщика — тот самый
# случай, из-за которого init перезапускал планировщик на каждом старте.
touch "$ZAPRET2_DIR/z2k-scheduler.sh"
sleep 1
touch "$ZAPRET2_DIR/z2k-tcp16-probe.sh"

_z2k_mtime() { date -r "$1" +%s 2>/dev/null || stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo ""; }
_z2k_sched_mtime() { _z2k_mtime "$1"; }

# Кусок планировщика: как он считает ЗАПИСЫВАЕМОЕ значение.
awk '/^_stamp_value="\$_self_mtime"$/,/^\[ -n "\$_stamp_value" \]/' "$SCHED" > "$SB/stamp.sh"
[ -s "$SB/stamp.sh" ] || { echo "[FAIL] не нашёл блок отметки в планировщике"; exit 1; }
_self_mtime=$(_z2k_mtime "$ZAPRET2_DIR/z2k-scheduler.sh")
# Последняя строка блока пишет в /tmp — перенаправим в песочницу.
sed 's#> /tmp/z2k-scheduler.mtime#> "'"$SB"'/stamp.out"#' "$SB/stamp.sh" > "$SB/stamp.run.sh"
. "$SB/stamp.run.sh"
wrote=$(cat "$SB/stamp.out" 2>/dev/null)

# Кусок init'а: как он считает ОЖИДАЕМОЕ значение.
_sch="$ZAPRET2_DIR/z2k-scheduler.sh"; _sch_probe="$ZAPRET2_DIR/z2k-tcp16-probe.sh"
awk '/^    _want=\$\(_z2k_sched_mtime "\$_sch"\)$/,/^    fi$/' "$INIT" > "$SB/want.sh"
[ -s "$SB/want.sh" ] || { echo "[FAIL] не нашёл блок ожидания в init"; exit 1; }
. "$SB/want.sh"

eq "проба новее планировщика: записано = ожидаемому (нет вечного перезапуска)" "$_want" "$wrote"
eq "записано именно время пробы" "$(_z2k_mtime "$_sch_probe")" "$wrote"

# Планировщик новее пробы — значение берётся от планировщика.
sleep 1
touch "$ZAPRET2_DIR/z2k-scheduler.sh"
_self_mtime=$(_z2k_mtime "$ZAPRET2_DIR/z2k-scheduler.sh")
. "$SB/stamp.run.sh"
wrote=$(cat "$SB/stamp.out" 2>/dev/null)
. "$SB/want.sh"
eq "планировщик новее: записано = ожидаемому" "$_want" "$wrote"

# Пробы нет вовсе — обе стороны берут время планировщика.
rm -f "$ZAPRET2_DIR/z2k-tcp16-probe.sh"
. "$SB/stamp.run.sh"
wrote=$(cat "$SB/stamp.out" 2>/dev/null)
. "$SB/want.sh"
eq "без файла пробы: записано = ожидаемому" "$_want" "$wrote"
: > "$ZAPRET2_DIR/z2k-tcp16-probe.sh"

# --- 2. «прогон завершён» ------------------------------------------------------
mkdir -p "$ZAPRET2_DIR/state"
eval "$(awk '/^_tcp16_done\(\) \{$/,/^\}$/' "$SCHED")"
[ "$(command -v _tcp16_done)" ] || { echo "[FAIL] не нашёл _tcp16_done в планировщике"; exit 1; }

st() { # st <started> <ts> <flag> <карта имён: yes|no>
    rm -f "$ZAPRET2_DIR/state/tcp16.flag" "$ZAPRET2_DIR/state/tcp16.flag.ts" \
          "$ZAPRET2_DIR/state/tcp16.flag.started" "$ZAPRET2_DIR/state/tcp16_sni.txt"
    [ "$1" = "-" ] || echo "$1" > "$ZAPRET2_DIR/state/tcp16.flag.started"
    [ "$2" = "-" ] || echo "$2" > "$ZAPRET2_DIR/state/tcp16.flag.ts"
    [ "$3" = "-" ] || echo "$3" > "$ZAPRET2_DIR/state/tcp16.flag"
    [ "$4" = "yes" ] && : > "$ZAPRET2_DIR/state/tcp16_sni.txt"
    _tcp16_done; echo $?
}
eq "блок найден, карта есть, завершение позже начала — завершён" "0" "$(st 100 200 1 yes)"
eq "блока нет, завершение позже начала — завершён" "0" "$(st 100 200 0 no)"
eq "оборван после флага: завершения нет — НЕ завершён" "1" "$(st 100 - 1 no)"
eq "оборван и перезапущен: начало новее завершения — НЕ завершён" "1" "$(st 300 200 1 yes)"
eq "блок найден, но карты имён нет — НЕ завершён" "1" "$(st 100 200 1 no)"
eq "ничего нет — НЕ завершён" "1" "$(st - - - no)"
eq "мусор вместо отметок — НЕ завершён" "1" "$(st abc xyz 1 yes)"

# --- 3. повтор включён для оборванного прогона ---------------------------------
# В блоке повтора обязаны стоять ОБЕ ветки: «измерено и завершено — молчим» и
# «флаг есть, но прогон оборвался — повторяем».
blk=$(awk '/^_tcp16_done\(\) \{$/ { f = 1 } f { print; n++ } n > 50 { exit }' "$SCHED")
case "$blk" in
    *'_tcp16_done; then'*) ok "повтор: ветка «измерено и завершено» проверяет завершённость" ;;
    *) no "повтор: ветка «измерено и завершено» проверяет завершённость" "_tcp16_done" "нет" ;;
esac
case "$blk" in
    *'прошлый прогон оборвался — повторяю'*) ok "повтор: оборванный прогон запускается заново" ;;
    *) no "повтор: оборванный прогон запускается заново" "run_task" "нет" ;;
esac
# И дроссель для незавершённого прогона — короткий (десять минут), а не час.
case "$blk" in
    *'_tcp16_done; then'*'_sni_gap=3600'*'_sni_gap=600'*) ok "незавершённому прогону — короткий дроссель" ;;
    *) no "незавершённому прогону — короткий дроссель" "600" "нет" ;;
esac

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
