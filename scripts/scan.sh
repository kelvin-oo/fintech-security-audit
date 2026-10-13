#!/usr/bin/env bash
# Tool evidence for fintech-security-audit. Runs whatever is installed, never
# installs anything, never prints a secret value.
#
#   bash scan.sh /path/to/repo [https://staging.example.com ...]
#
# URLs must be staging or local. Production URLs are refused by name match;
# that check is a guard, not a substitute for the user's scope answer.

set -uo pipefail

REPO="${1:?usage: scan.sh /path/to/repo [staging-url ...]}"
shift || true
REPO="$(cd "$REPO" && pwd)"
OUT="${AUDIT_DIR:-audit}/evidence"
mkdir -p "$OUT"
STAMP="$(date +%Y-%m-%d)"
SUMMARY="$OUT/scan-summary-$STAMP.md"
echo "# Tool scan, $STAMP" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Repository: \`$(basename "$REPO")\`" >> "$SUMMARY"
echo "" >> "$SUMMARY"

note() { echo "$*" | tee -a "$SUMMARY"; }

# ── 1. Dependencies ──
note "## Dependencies"
found_pkg=0
while IFS= read -r lock; do
  dir="$(dirname "$lock")"
  rel="${dir#$REPO}"; rel="${rel:-/}"
  found_pkg=1
  case "$(basename "$lock")" in
    package-lock.json)
      if command -v npm >/dev/null; then
        (cd "$dir" && npm audit --json 2>/dev/null) > "$OUT/npm-audit${rel//\//_}.json"
        python3 - "$OUT/npm-audit${rel//\//_}.json" "$rel" <<'PY' | tee -a "$SUMMARY"
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    v = d.get("metadata", {}).get("vulnerabilities", {})
    print(f"- npm `{sys.argv[2]}`: critical {v.get('critical',0)}, high {v.get('high',0)}, moderate {v.get('moderate',0)}, low {v.get('low',0)}")
except Exception as e:
    print(f"- npm `{sys.argv[2]}`: could not read audit output ({e.__class__.__name__})")
PY
      fi ;;
    pnpm-lock.yaml)
      command -v pnpm >/dev/null && (cd "$dir" && pnpm audit --json 2>/dev/null) > "$OUT/pnpm-audit${rel//\//_}.json" && note "- pnpm \`$rel\`: see pnpm-audit${rel//\//_}.json" ;;
    yarn.lock)
      command -v yarn >/dev/null && (cd "$dir" && yarn audit --json 2>/dev/null) > "$OUT/yarn-audit${rel//\//_}.json" && note "- yarn \`$rel\`: see yarn-audit${rel//\//_}.json" ;;
    requirements.txt|poetry.lock)
      if command -v pip-audit >/dev/null; then
        (cd "$dir" && pip-audit -f json 2>/dev/null) > "$OUT/pip-audit${rel//\//_}.json"; note "- pip \`$rel\`: see pip-audit${rel//\//_}.json"
      else
        note "- python \`$rel\`: pip-audit not installed, skipped"
      fi ;;
  esac
done < <(find "$REPO" -maxdepth 4 \( -name node_modules -o -name .git -o -name .next -o -name dist \) -prune -o \
          \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name requirements.txt -o -name poetry.lock \) -print)
[ "$found_pkg" = 0 ] && note "- No lock files found"
note ""

# ── 2. Secrets (working tree and git history) ──
note "## Secrets"
if command -v gitleaks >/dev/null; then
  gitleaks detect --source "$REPO" --redact --report-format json --report-path "$OUT/gitleaks.json" >/dev/null 2>&1
  python3 - "$OUT/gitleaks.json" <<'PY' | tee -a "$SUMMARY"
import json, sys, collections
try:
    rows = json.load(open(sys.argv[1]))
except Exception:
    rows = []
c = collections.Counter(r.get("RuleID", "?") for r in rows)
print(f"- gitleaks (history included, values redacted): {len(rows)} hit(s)" + ("" if not c else ": " + ", ".join(f"{k} {v}" for k, v in c.most_common())))
for r in rows[:40]:
    print(f"  - {r.get('RuleID')} in `{r.get('File')}` line {r.get('StartLine')}, commit {str(r.get('Commit',''))[:8]}")
PY
else
  # Pattern scan. Prints the file, line and kind of secret only, never the value.
  PATTERNS='(sk|rk|whsec)_live_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z_-]{30,}|[a-z]+://[^[:space:]:/@]+:[^[:space:]@/]{6,}@'
  {
    echo "- gitleaks not installed; pattern scan used (working tree and git history; values never shown)"
    # -H forces "file:line:match" even for one file. awk rebuilds every line
    # from its parts, so a value can never pass through unformatted.
    (cd "$REPO" && git ls-files -z 2>/dev/null | xargs -0 grep -HnIoE "$PATTERNS" 2>/dev/null) \
      | awk -F: '{ f=$1; l=$2; m=$0; sub(/^[^:]*:[^:]*:/, "", m);
                   if (l ~ /^[0-9]+$/) printf "  - working tree: `%s` line %s (starts `%s****`)\n", f, l, substr(m, 1, 6);
                   else print "  - working tree: a match (location unreadable, value hidden)" }' | head -60
    if [ -d "$REPO/.git" ]; then
      (cd "$REPO" && git log -p --all --no-color 2>/dev/null | grep -oE "$PATTERNS") \
        | cut -c1-6 | sort | uniq -c \
        | awk '{printf "  - git history: %s match(es) starting `%s****`\n", $1, $2}' | head -40
    fi
  } | tee -a "$SUMMARY"
fi
note ""

# ── 3. Static analysis ──
note "## Static analysis"
if command -v semgrep >/dev/null; then
  semgrep scan --config auto --json --quiet "$REPO" > "$OUT/semgrep.json" 2>/dev/null
  python3 - "$OUT/semgrep.json" <<'PY' | tee -a "$SUMMARY"
import json, sys, collections
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {"results": []}
r = d.get("results", [])
c = collections.Counter(x.get("extra", {}).get("severity", "?") for x in r)
print(f"- semgrep: {len(r)} result(s) " + ", ".join(f"{k} {v}" for k, v in c.items()) + " (triage before turning into findings)")
PY
else
  note "- semgrep not installed, skipped"
fi
note ""

# ── 4. Security headers (staging and local only) ──
note "## Security headers"
if [ "$#" -eq 0 ]; then
  note "- No URLs given, skipped"
fi
for url in "$@"; do
  host="$(echo "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
  case "$host" in
    localhost|127.0.0.1|*.localhost|*.test|*staging*|*stage*|*dev*|*sandbox*|*preview*) ;;
    *) note "- \`$url\` refused: does not look like staging or local. Production is never scanned."; continue ;;
  esac
  h="$(curl -s -I -L --max-time 15 "$url" | tr -d '\r' | tr 'A-Z' 'a-z')"
  if [ -z "$h" ]; then note "- \`$url\`: no response"; continue; fi
  missing=""
  for want in strict-transport-security content-security-policy x-content-type-options referrer-policy permissions-policy; do
    echo "$h" | grep -q "^$want:" || missing="$missing $want"
  done
  echo "$h" | grep -qE "^x-frame-options:|frame-ancestors" || missing="$missing frame-protection"
  leak="$(echo "$h" | grep -E '^(server|x-powered-by):' | tr '\n' ' ')"
  note "- \`$url\`: missing [${missing# }]${leak:+, reveals: $leak}"
done
note ""
echo "Summary written to $SUMMARY"
