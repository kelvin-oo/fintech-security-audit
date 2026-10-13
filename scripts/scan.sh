#!/usr/bin/env bash
# Tool evidence for fintech-security-audit. Runs whatever is installed, never
# installs anything, never prints a secret value.
#
#   bash scan.sh [--online] [--semgrep-rules PATH] /path/to/repo [staging-url ...]
#
# Offline by default: nothing is sent anywhere. Dependency files are listed for
# review by hand instead of being checked against public advisory databases.
# --online allows the checks that send package lists to public databases
# (npm, Packagist, PyPI, Go, RubyGems, NuGet, crates.io) and semgrep's
# downloaded rules. Only use it when the code owner has said yes.
#
# URLs are only contacted when given, and must be staging or local.

set -uo pipefail

ONLINE=0
RULES=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --online) ONLINE=1; shift ;;
    --semgrep-rules) RULES="${2:?--semgrep-rules needs a path}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) break ;;
  esac
done

REPO="${1:?usage: scan.sh [--online] [--semgrep-rules PATH] /path/to/repo [staging-url ...]}"
shift || true
REPO="$(cd "$REPO" && pwd)"
OUT="${AUDIT_DIR:-audit}/evidence"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

# The evidence describes weaknesses. Refuse to write it where git would pick it
# up. Checked before anything is created.
probe="$OUT"; while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
if top="$(git -C "$probe" rev-parse --show-toplevel 2>/dev/null)"; then
  if ! git -C "$top" check-ignore -q "$OUT/x" 2>/dev/null; then
    echo "Refusing to write evidence: $OUT is inside a git repository and not ignored."
    echo "Add it to the repository's local ignore list (never committed):"
    rel="${OUT#$top/}"; rel="${rel%/evidence}"
    echo "  echo '/$rel/' >> \"$top/.git/info/exclude\""
    exit 2
  fi
fi
mkdir -p "$OUT"

STAMP="$(date +%Y-%m-%d)"
SUMMARY="$OUT/scan-summary-$STAMP.md"
{
  echo "# Tool scan, $STAMP"
  echo ""
  echo "Repository: \`$(basename "$REPO")\` · Mode: $([ "$ONLINE" = 1 ] && echo "online (package lists sent to public advisory databases)" || echo "offline (nothing sent anywhere)")"
  echo ""
} > "$SUMMARY"

note() { echo "$*" | tee -a "$SUMMARY"; }
has() { command -v "$1" >/dev/null 2>&1; }
slug() { local r="${1#$REPO}"; r="${r:-/root}"; echo "${r//\//_}"; }

# Writes "name version" lines for one lock file to an inventory and prints the count.
inventory() {
  python3 - "$1" "$2" <<'PY'
import json, re, sys, os
path, out = sys.argv[1], sys.argv[2]
name = os.path.basename(path)
rows = []
try:
    text = open(path, encoding="utf-8", errors="replace").read()
    if name == "composer.lock":
        d = json.loads(text)
        rows = [f"{p['name']} {p.get('version','')}" for p in d.get("packages", []) + d.get("packages-dev", [])]
    elif name == "package-lock.json":
        d = json.loads(text)
        pk = d.get("packages") or {}
        rows = [f"{k.split('node_modules/')[-1]} {v.get('version','')}" for k, v in pk.items() if k]
        if not rows:
            rows = [f"{k} {v.get('version','')}" for k, v in (d.get("dependencies") or {}).items()]
    elif name == "yarn.lock":
        rows = sorted(set(re.findall(r'^"?(@?[^@\s"]+)@', text, re.M)))
    elif name == "pnpm-lock.yaml":
        rows = sorted(set(re.findall(r"^\s{2}/?(@?[^:\s(]+)[@/]([0-9][^:(\s]*)", text, re.M)))
        rows = [f"{a} {b}" for a, b in rows]
    elif name == "go.sum":
        rows = sorted({" ".join(l.split()[:2]).replace("/go.mod", "") for l in text.splitlines() if l.strip()})
    elif name == "Gemfile.lock":
        rows = re.findall(r"^    (\S+) \(([^)]+)\)", text, re.M); rows = [f"{a} {b}" for a, b in rows]
    elif name in ("requirements.txt",):
        rows = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith(("#", "-"))]
    elif name == "poetry.lock":
        rows = re.findall(r'name = "([^"]+)"\nversion = "([^"]+)"', text); rows = [f"{a} {b}" for a, b in rows]
    elif name == "Cargo.lock":
        rows = re.findall(r'name = "([^"]+)"\nversion = "([^"]+)"', text); rows = [f"{a} {b}" for a, b in rows]
    elif name == "pom.xml":
        rows = re.findall(r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", text); rows = [f"{a} {b}" for a, b in rows]
    elif name.startswith("build.gradle"):
        rows = re.findall(r"""(?:implementation|api|compile|runtimeOnly)\s*\(?\s*['"]([^'"]+)['"]""", text)
    elif name.endswith(".csproj") or name == "packages.lock.json":
        rows = re.findall(r'PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text); rows = [f"{a} {b}" for a, b in rows]
except Exception as e:
    rows = []
open(out, "w").write("\n".join(rows) + ("\n" if rows else ""))
print(len(rows))
PY
}

# ── 1. Dependencies ──
note "## Dependencies"
found=0
while IFS= read -r lock; do
  found=1
  dir="$(dirname "$lock")"; base="$(basename "$lock")"; rel="${lock#$REPO/}"
  inv="$OUT/deps$(slug "$dir")-$base.txt"
  n="$(inventory "$lock" "$inv")"
  checked=""
  if [ "$ONLINE" = 1 ]; then
    case "$base" in
      package-lock.json) has npm && { (cd "$dir" && npm audit --json 2>/dev/null) > "$inv.audit.json"; checked="npm audit"; } ;;
      pnpm-lock.yaml)    has pnpm && { (cd "$dir" && pnpm audit --json 2>/dev/null) > "$inv.audit.json"; checked="pnpm audit"; } ;;
      yarn.lock)         has yarn && { (cd "$dir" && yarn audit --json 2>/dev/null) > "$inv.audit.json"; checked="yarn audit"; } ;;
      composer.lock)     has composer && { (cd "$dir" && composer audit --locked --format=json 2>/dev/null) > "$inv.audit.json"; checked="composer audit"; } ;;
      go.sum)            has govulncheck && { (cd "$dir" && govulncheck ./... 2>&1) > "$inv.audit.txt"; checked="govulncheck"; } ;;
      Gemfile.lock)      has bundle-audit && { (cd "$dir" && bundle-audit check --update 2>&1) > "$inv.audit.txt"; checked="bundle-audit"; } ;;
      requirements.txt)  has pip-audit && { pip-audit -r "$lock" -f json 2>/dev/null > "$inv.audit.json"; checked="pip-audit"; } ;;
      poetry.lock)       has pip-audit && { (cd "$dir" && pip-audit -f json 2>/dev/null) > "$inv.audit.json"; checked="pip-audit"; } ;;
      Cargo.lock)        has cargo-audit && { (cd "$dir" && cargo audit --json 2>/dev/null) > "$inv.audit.json"; checked="cargo audit"; } ;;
      *.csproj|packages.lock.json) has dotnet && { (cd "$dir" && dotnet list package --vulnerable --include-transitive 2>&1) > "$inv.audit.txt"; checked="dotnet list package --vulnerable"; } ;;
    esac
  fi
  if [ -n "$checked" ]; then
    summary="$(python3 - "$inv".audit.* <<'PY'
import json, sys, re
p = sys.argv[1]
t = open(p, errors="replace").read()
try:
    d = json.loads(t)
except Exception:
    hits = len(re.findall(r"(?im)^(vulnerability|name:|id:\s*GO-|\s*>\s)", t))
    print(f"{hits} possible advisory line(s), see {p.rsplit('/',1)[-1]}"); sys.exit()
if isinstance(d, dict) and "metadata" in d and "vulnerabilities" in d.get("metadata", {}):
    v = d["metadata"]["vulnerabilities"]; print(", ".join(f"{k} {v.get(k,0)}" for k in ("critical","high","moderate","low")))
elif isinstance(d, dict) and "advisories" in d:
    a = d["advisories"]; n = sum(len(x) for x in a.values()) if isinstance(a, dict) else len(a); print(f"{n} advisory(ies)")
elif isinstance(d, dict) and "dependencies" in d:
    print(f"{sum(len(x.get('vulns',[])) for x in d['dependencies'])} known vulnerability(ies)")
elif isinstance(d, dict) and "vulnerabilities" in d:
    print(f"{d['vulnerabilities'].get('count', '?')} known vulnerability(ies)")
else:
    print(f"see {p.rsplit('/',1)[-1]}")
PY
)"
    note "- \`$rel\`: $n package(s), $checked: $summary"
  elif [ "$ONLINE" = 1 ]; then
    note "- \`$rel\`: $n package(s); no checker installed, review the inventory by hand (\`$(basename "$inv")\`)"
  else
    note "- \`$rel\`: $n package(s); offline, review the inventory by hand (\`$(basename "$inv")\`)"
  fi
done < <(find "$REPO" -maxdepth 5 \( -name node_modules -o -name vendor -o -name .git -o -name .next -o -name dist -o -name target -o -name bin -o -name obj \) -prune -o \
          \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name composer.lock -o -name go.sum \
             -o -name Gemfile.lock -o -name requirements.txt -o -name poetry.lock -o -name Cargo.lock -o -name pom.xml \
             -o -name 'build.gradle' -o -name 'build.gradle.kts' -o -name '*.csproj' -o -name packages.lock.json \) -print | sort)
[ "$found" = 0 ] && note "- No dependency files found"
for pair in "composer.json:composer.lock" "Gemfile:Gemfile.lock" "Cargo.toml:Cargo.lock"; do
  m="${pair%%:*}"; l="${pair##*:}"
  if [ -f "$REPO/$m" ] && [ ! -f "$REPO/$l" ]; then note "- \`$m\` has no \`$l\`: versions are not pinned, which is itself worth a finding"; fi
done
note ""

# ── 2. Secrets (working tree and git history) ──
note "## Secrets"
if has gitleaks; then
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
  PATTERNS='(sk|rk|whsec)_live_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z_-]{30,}|[a-z]+://[^[:space:]:/@]+:[^[:space:]@/]{6,}@|APP_KEY=base64:[A-Za-z0-9+/=]{20,}'
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
    # Committed environment files are a finding on their own, whatever they contain.
    (cd "$REPO" && git ls-files 2>/dev/null | grep -E '(^|/)\.env(\.[A-Za-z0-9_-]+)?$' | grep -vE '\.(example|sample|dist|template)$') \
      | awk '{printf "  - committed environment file: `%s`\n", $0}'
  } | tee -a "$SUMMARY"
fi
note ""

# ── 3. Static analysis ──
note "## Static analysis"
if ! has semgrep; then
  note "- semgrep not installed, skipped"
elif [ -n "$RULES" ]; then
  semgrep scan --config "$RULES" --metrics=off --json --quiet "$REPO" > "$OUT/semgrep.json" 2>/dev/null
  SEMGREP_RAN=1
elif [ "$ONLINE" = 1 ]; then
  semgrep scan --config auto --json --quiet "$REPO" > "$OUT/semgrep.json" 2>/dev/null
  SEMGREP_RAN=1
else
  note "- semgrep skipped: offline, and no local rules given (--semgrep-rules PATH)"
fi
if [ "${SEMGREP_RAN:-0}" = 1 ]; then
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
fi
note ""

# ── 4. Security headers (only URLs given, staging and local only) ──
note "## Security headers"
[ "$#" -eq 0 ] && note "- No URLs given, skipped"
for url in "$@"; do
  host="$(echo "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
  case "$host" in
    localhost|127.0.0.1|*.localhost|*.test|*staging*|*stage*|*dev*|*sandbox*|*preview*|*uat*) ;;
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
