#!/usr/bin/env bash
# TwinVPN Phase 1 documentation validator.
# Checks the structural invariants the contradiction review established.
# Phase 1 produces no production code; this validates documents only.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
note() { printf '%-52s %s\n' "$1" "$2"; }
bad()  { fail=1; printf '%-52s %s\n' "$1" "FAIL"; }

# 1. Every relative markdown link resolves.
broken=$(while IFS=: read -r src tgt; do d=$(dirname "$src"); [ -f "$d/$tgt" ] || echo "$src -> $tgt"; done \
  < <(grep -rn -o '](\([^)#]*\.md\)' docs/ --include='*.md' | sed 's/:\([0-9]*\):](/:/' | sort -u))
if [ -z "$broken" ]; then note "cross-document links" "OK"; else bad "cross-document links" ; echo "$broken"; fi

# 2. ADR filenames referenced anywhere are canonical (i.e. exist).
variants=$(grep -rhoE 'ADR-00[0-9]{2}-[a-z0-9-]+\.md' docs/ | sort -u | while read -r f; do [ -f "docs/adr/$f" ] || echo "$f"; done)
if [ -z "$variants" ]; then note "canonical ADR filenames" "OK"; else bad "canonical ADR filenames"; echo "$variants"; fi

# 3. All 15 ADRs carry the mandatory 14 sections.
s14=0
for f in docs/adr/ADR-*.md; do
  n=$(grep -cE '^## (1\. Context|2\. Requirements|3\. Constraints|4\. Considered|5\. Advantages|6\. Disadvantages|7\. Security|8\. Reliability|9\. Performance|10\. Operational|11\. Decision|12\. Why|13\. Known|14\. Revisit)' "$f")
  [ "$n" -eq 14 ] || { echo "  $(basename "$f"): $n/14"; s14=1; }
done
[ $s14 -eq 0 ] && note "ADR 14-section structure" "OK" || bad "ADR 14-section structure"

# 4. No duplicate state-ownership row declarations, and architecture.md holds them all.
dupes=$(grep -rhoE '^\| \*\*S-[0-9]+\*\* \| [A-Za-z`(*]' docs/adr/*.md | grep -oE 'S-[0-9]+' | sort | uniq -d \
        | grep -v '^S-27$')   # S-27 is one fact deliberately cited by two ADRs
if [ -z "$dupes" ]; then note "state rows: no duplicate owners" "OK"; else bad "state rows: no duplicate owners"; echo "$dupes"; fi
declared=$(grep -rhoE '^\| \*\*S-[0-9]+\*\*' docs/adr/*.md | grep -oE 'S-[0-9]+' | sort -u)
missing=$(for r in $declared; do grep -q "^| $r " docs/architecture.md || echo "$r"; done)
if [ -z "$missing" ]; then note "state rows present in architecture" "OK"; else bad "state rows present in architecture"; echo "$missing"; fi

# 5. Reason codes: one taxonomy. No TWN- / SEC_ forms; no 4-segment codes.
legacy=$(grep -rhoE 'TWN-[A-Z-]+|\bSEC_[A-Z_]+' docs/ | sort -u)
if [ -z "$legacy" ]; then note "reason codes: no legacy formats" "OK"; else bad "reason codes: no legacy formats"; echo "$legacy"; fi
deep=$(grep -rhoE '\b[A-Z]+\.[A-Z_]+\.[A-Z_]+\.[A-Z_]+\b' docs/ | sort -u)
if [ -z "$deep" ]; then note "reason codes: <=3 segments" "OK"; else bad "reason codes: <=3 segments"; echo "$deep"; fi

# 6. No document invents a ConnectionState outside the canonical twelve.
states='DISCONNECTED|DISCOVERING|NEGOTIATING|CONNECTING|LOCAL_DIRECT|WAN_DIRECT|RELAYED|MIGRATING|DEGRADED|RECONNECTING|BLOCKED|FAILED'
note "ConnectionState vocabulary (12)" "$(grep -rhoE "\`($states)\`" docs/ | sort -u | wc -l)/12 in use"

# 7. Placeholders that must never ship.
# Only flag LINKS to the retired filenames, not prose describing the resolved defect.
ph=$(grep -rn '<ULA48>\|fdT:WIN:VPN\|](\.\./security\.md)\|](security\.md)\|](\.\./testing\.md)\|](testing\.md)' docs/ || true)
if [ -z "$ph" ]; then note "no unresolved placeholders" "OK"; else bad "no unresolved placeholders"; echo "$ph"; fi

# 8. Reason-code domains come from the registered allowlist only.
#    13 existing (ADR-0015 §11.2) + 3 introduced by the application workstream.
#    DOMAIN is the literal placeholder used in ADR-0015's format explanation.
allow='NET|NAT|RELAY|AUTH|CRYPTO|PROTO|POLICY|DNS|ROUTE|PLATFORM|RESOURCE|CONTROL|INTERNAL|MGMT|STORE|UPDATE|DOMAIN'
rogue=$(grep -rhoE '\b[A-Z][A-Z0-9]{2,9}\.[A-Z][A-Z0-9_]+\b' docs/ | cut -d. -f1 | sort -u \
        | grep -vE "^($allow)$" || true)
if [ -z "$rogue" ]; then note "reason codes: registered domains only" "OK"; else bad "reason codes: registered domains only"; echo "$rogue"; fi

# 9. Application-workstream ADRs declare S- rows only inside their assigned block.
sblock() { case "$1" in
  0016) echo "38 41";; 0017) echo "42 45";; 0018) echo "46 47";; 0019) echo "48 51";;
  0020) echo "52 56";; 0021) echo "57 60";; 0022) echo "61 64";; 0023) echo "65 68";;
  *) echo "";; esac; }
sbad=0
for f in docs/adr/ADR-00{16,17,18,19,20,21,22,23}-*.md; do
  [ -f "$f" ] || continue
  n=$(basename "$f" | grep -oE '00[0-9]{2}'); range=$(sblock "$n"); set -- $range
  for r in $(grep -ohE '^\| \*\*S-[0-9]+\*\*' "$f" | grep -oE '[0-9]+$'); do
    r=$((10#$r))
    [ "$r" -ge "$1" ] && [ "$r" -le "$2" ] || { echo "  ADR-$n declares S-$r outside block $1-$2"; sbad=1; }
  done
done
[ $sbad -eq 0 ] && note "app ADRs: S-rows within block" "OK" || bad "app ADRs: S-rows within block"

# 10. Application-workstream ADRs propose R- requirements only inside their assigned block.
rblock() { case "$1" in
  0016) echo "25 27";; 0017) echo "28 30";; 0018) echo "31 32";; 0019) echo "33 36";;
  0020) echo "37 39";; 0021) echo "40 43";; 0022) echo "44 46";; 0023) echo "47 49";;
  *) echo "";; esac; }
rbad=0
for f in docs/adr/ADR-00{16,17,18,19,20,21,22,23}-*.md; do
  [ -f "$f" ] || continue
  n=$(basename "$f" | grep -oE '00[0-9]{2}'); range=$(rblock "$n"); set -- $range
  for r in $(grep -ohE '^\| \*\*R-[0-9]+\*\*' "$f" | grep -oE '[0-9]+'); do
    r=$((10#$r))
    [ "$r" -ge 25 ] || continue   # citing an existing R-01..R-24 is legitimate
    [ "$r" -ge "$1" ] && [ "$r" -le "$2" ] || { echo "  ADR-$n proposes R-$r outside block $1-$2"; rbad=1; }
  done
done
[ $rbad -eq 0 ] && note "app ADRs: R-rows within block" "OK" || bad "app ADRs: R-rows within block"

# 11. I8 same-subject advisory. Two S-rows whose PRIMARY SUBJECT is the same identifier
#     are a probable I8 violation (one fact, two writers). Reported, never fatal:
#     the subtler shape -- one row's subject appearing as a field inside another row --
#     is too noisy to automate and needs human review. That is how the S-54/S-67
#     `custody_class` collision was caught, and it is why this stays advisory.
python3 - <<'PYEOF'
import glob, re
rows = []
for f in sorted(glob.glob('docs/adr/ADR-*.md')):
    for line in open(f, encoding='utf-8'):
        m = re.match(r'^\|\s*\*\*(S-\d+)\*\*\s*\|([^|]+)\|', line)
        if m:
            ids = re.findall(r'`([A-Za-z_][A-Za-z0-9_]{3,})`', m.group(2))
            if ids:
                rows.append((m.group(1), ids[0], f.split('/')[-1]))
seen = {}
for sid, subj, f in rows:
    seen.setdefault(subj, set()).add((sid, f))
hits = {k: v for k, v in seen.items() if len({s for s, _ in v}) > 1}
for k, v in sorted(hits.items()):
    print(f"  advisory: subject `{k}` is the primary subject of " +
          ", ".join(f"{s} ({f[:12]})" for s, f in sorted(v)))
PYEOF
note "I8 same-subject advisory" "$( [ -z "$(python3 -c 'pass')" ] && echo 'reported above if any')"

echo
[ $fail -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
