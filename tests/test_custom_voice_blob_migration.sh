#!/bin/sh
# tests/test_custom_voice_blob_migration.sh
#
# 25.10.2026: голосовой пул переехал с quic_dbankcloud на
# quic_initial_steamcommunity_com, старый блоб снят с регистрации. Пользовательские
# стратегии из панели несут имя старого блоба — без переноса nfqws2 не поднимется.
# Проверяем замену имени, сохранность остального, похожие имена, снимок,
# идемпотентность и отметку.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
awk '/^_z2k_migrate_custom_voice_blob_v1\(\)/,/^}/' "$ROOT/files/S99zapret2.new" > "$TMP/migrate.sh"
. "$TMP/migrate.sh"
ZAPRET_BASE=$TMP/base
export ZAPRET_BASE
D=$ZAPRET_BASE/lists/custom-strategies
mkdir -p "$D"
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf '[FAIL] %s\n' "$1"; }

printf '%s\n' '# мой голос' '--lua-desync=fake:payload=all:blob=quic_dbankcloud:repeats=8:strategy=1' \
    '--lua-desync=fake:payload=all:blob=quic_dbankcloud' > "$D/discord_udp.txt"
printf '%s\n' '--lua-desync=fake:blob=quic_dbankcloud_x:repeats=2' > "$D/quic.txt"
printf '%s\n' '--lua-desync=multisplit:pos=1' > "$D/rkn_tcp.txt"
cp "$D/discord_udp.txt" "$TMP/orig"; cp "$D/rkn_tcp.txt" "$TMP/rkn_orig"

_z2k_migrate_custom_voice_blob_v1 >/dev/null

grep -q 'blob=quic_initial_steamcommunity_com:repeats=8:strategy=1' "$D/discord_udp.txt" && ok "blob name replaced, repeats kept" || no "blob name replaced, repeats kept"
grep -qx -- '--lua-desync=fake:payload=all:blob=quic_initial_steamcommunity_com' "$D/discord_udp.txt" && ok "blob at end of line replaced" || no "blob at end of line replaced"
grep -q 'quic_dbankcloud' "$D/discord_udp.txt" && no "no old name left" || ok "no old name left"
grep -qx '# мой голос' "$D/discord_udp.txt" && ok "comments kept" || no "comments kept"
grep -q 'blob=quic_dbankcloud_x' "$D/quic.txt" && ok "longer similar name untouched" || no "longer similar name untouched"
[ ! -e "$D/quic.txt.pre-voice-blob-v1" ] && ok "untouched file gets no snapshot" || no "untouched file gets no snapshot"
cmp -s "$D/rkn_tcp.txt" "$TMP/rkn_orig" && ok "unrelated file unchanged" || no "unrelated file unchanged"
cmp -s "$D/discord_udp.txt.pre-voice-blob-v1" "$TMP/orig" && ok "snapshot of original kept" || no "snapshot of original kept"
[ -f "$ZAPRET_BASE/state/custom-voice-blob-v1.done" ] && ok "done marker set" || no "done marker set"

# идемпотентность: второй прогон ничего не меняет
cp "$D/discord_udp.txt" "$TMP/after1"
_z2k_migrate_custom_voice_blob_v1 >/dev/null
cmp -s "$D/discord_udp.txt" "$TMP/after1" && ok "second run is a no-op" || no "second run is a no-op"

# нет каталога — тихо, с отметкой
ZAPRET_BASE=$TMP/empty; export ZAPRET_BASE; mkdir -p "$ZAPRET_BASE"
_z2k_migrate_custom_voice_blob_v1 >/dev/null && ok "no custom dir: returns 0" || no "no custom dir: returns 0"
[ -f "$ZAPRET_BASE/state/custom-voice-blob-v1.done" ] && ok "no custom dir: marker set" || no "no custom dir: marker set"

printf '\nPASSED: %d\nFAILED: %d\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
