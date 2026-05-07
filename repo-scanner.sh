#!/usr/bin/env bash
# repo-scanner.sh — Security scanner focused on credential theft & data exfiltration

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR_SCAN="$SCRIPT_DIR/tmp/scan-$$"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$TMPDIR_SCAN" "$OUT_DIR"
trap 'rm -rf "$TMPDIR_SCAN"' EXIT

# ── Dependencies ───────────────────────────────────────────────────────────────
BREW_TOOLS="gitleaks semgrep yara trufflehog"
PIPX_TOOLS="detect-secrets"

check_deps() {
  local missing_brew="" missing_pipx="" outdated_brew=""

  for t in $BREW_TOOLS; do
    command -v "$t" &>/dev/null || missing_brew="$missing_brew $t"
  done
  for t in $PIPX_TOOLS; do
    command -v "$t" &>/dev/null || missing_pipx="$missing_pipx $t"
  done
  for t in $BREW_TOOLS; do
    if command -v "$t" &>/dev/null; then
      brew outdated --quiet 2>/dev/null | grep -q "^$t$" && outdated_brew="$outdated_brew $t"
    fi
  done

  if [[ -n "$missing_brew" || -n "$missing_pipx" ]]; then
    echo -e "${YELLOW}Missing dependencies:${RESET}${missing_brew}${missing_pipx}"
    read -rp "  Install now? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
      for t in $missing_brew;  do brew install "$t";  done
      for t in $missing_pipx; do pipx install "$t"; done
    fi
  fi

  if [[ -n "$outdated_brew" ]]; then
    echo -e "${YELLOW}Updates available:${RESET}${outdated_brew}"
    read -rp "  Update now? [y/N]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] && brew upgrade $outdated_brew
  fi
}

# ── Input ──────────────────────────────────────────────────────────────────────
check_deps
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║        REPO SECURITY SCANNER             ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${RESET}"
echo ""
REPO_URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -z "$REPO_URL" ]]; then
  read -rp "  Repo URL: " REPO_URL
else
  echo -e "  Repo URL: ${BOLD}$REPO_URL${RESET}"
fi
[[ -z "$REPO_URL" ]] && echo "No URL provided." && exit 1

REPO_NAME=$(basename "$REPO_URL" .git)
CLONE_DIR="$TMPDIR_SCAN/$REPO_NAME"

echo -e "\n  ${CYAN}Cloning...${RESET}"
git clone --depth=1 --quiet "$REPO_URL" "$CLONE_DIR" 2>&1 || { echo -e "${RED}Clone failed.${RESET}"; exit 1; }

# ── Check engine ──────────────────────────────────────────────────────────────
GREP_INCLUDES=(-rIl
  --include="*.js" --include="*.ts" --include="*.py" --include="*.sh"
  --include="*.env" --include="*.json" --include="*.yml" --include="*.yaml"
  --include="*.rb" --include="*.php" --include="*.go" --include="*.java")

run_grep() {
  local varname="$1" pattern="$2" exclude="${3:-}"
  local args=("${GREP_INCLUDES[@]}")
  [[ -n "$exclude" ]] && args+=(--exclude="$exclude")
  local hits count
  hits=$(grep -E "${args[@]}" "$pattern" "$CLONE_DIR" 2>/dev/null | head -20 || true)
  count=$(printf '%s' "$hits" | grep -c . 2>/dev/null || true)
  if [[ "$count" -gt 0 ]]; then
    eval "RESULT_${varname}=\"FOUND ($count files)\""
    eval "DETAIL_${varname}=\"$(echo "$hits" | head -3 | sed "s|$CLONE_DIR/||" | sed 's/"/\\"/g')\""
  else
    eval "RESULT_${varname}=\"CLEAN\""
    eval "DETAIL_${varname}=\"\""
  fi
}

# ── 1. Gitleaks — secrets & credential theft ──────────────────────────────────
echo -e "  ${CYAN}Running gitleaks...${RESET}"
GITLEAKS_OUT="$TMPDIR_SCAN/gitleaks.json"
if command -v gitleaks &>/dev/null; then
  gitleaks detect --source "$CLONE_DIR" --report-format json \
    --report-path "$GITLEAKS_OUT" --no-git --exit-code 0 -q 2>/dev/null || true
  GL_COUNT=$(python3 -c "import json,sys; d=json.load(open('$GITLEAKS_OUT')); print(len(d))" 2>/dev/null || echo 0)
  if [[ "$GL_COUNT" -gt 0 ]]; then
    RESULT_GITLEAKS="FOUND ($GL_COUNT secrets)"
    DETAIL_GITLEAKS=$(python3 -c "
import json
d=json.load(open('$GITLEAKS_OUT'))
seen=set()
for i in d[:3]:
    f=i.get('File','?')
    r=i.get('RuleID','?')
    line='%s (%s)' % (f,r)
    if line not in seen:
        seen.add(line)
        print(line)
" 2>/dev/null || true)
  else
    RESULT_GITLEAKS="CLEAN"
    DETAIL_GITLEAKS=""
  fi
else
  RESULT_GITLEAKS="SKIPPED (not found)"
  DETAIL_GITLEAKS=""
fi

# ── 2. Semgrep — exfiltration & malicious patterns ───────────────────────────
echo -e "  ${CYAN}Running semgrep...${RESET}"
SEMGREP_OUT="$TMPDIR_SCAN/semgrep.json"
if command -v semgrep &>/dev/null; then
  semgrep --config "p/security-audit" --config "p/secrets" \
    --json --output "$SEMGREP_OUT" "$CLONE_DIR" \
    --quiet --no-error 2>/dev/null || true
  SG_COUNT=$(python3 -c "import json,sys; d=json.load(open('$SEMGREP_OUT')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
  if [[ "$SG_COUNT" -gt 0 ]]; then
    RESULT_SEMGREP="FOUND ($SG_COUNT matches)"
    DETAIL_SEMGREP=$(python3 -c "
import json
d=json.load(open('$SEMGREP_OUT'))
seen=set()
for r in d.get('results',[])[:3]:
    f=r.get('path','?').replace('$CLONE_DIR/','')
    rule=r.get('check_id','?').split('.')[-1]
    line='%s (%s)' % (f,rule)
    if line not in seen:
        seen.add(line)
        print(line)
" 2>/dev/null || true)
  else
    RESULT_SEMGREP="CLEAN"
    DETAIL_SEMGREP=""
  fi
else
  RESULT_SEMGREP="SKIPPED (not found)"
  DETAIL_SEMGREP=""
fi

# ── 3. detect-secrets — secrets in code ──────────────────────────────────────
echo -e "  ${CYAN}Running detect-secrets...${RESET}"
DS_OUT="$TMPDIR_SCAN/detect-secrets.json"
if command -v detect-secrets &>/dev/null; then
  detect-secrets scan "$CLONE_DIR" > "$DS_OUT" 2>/dev/null || true
  DS_COUNT=$(python3 -c "
import json
d=json.load(open('$DS_OUT'))
print(sum(len(v) for v in d.get('results',{}).values()))
" 2>/dev/null || echo 0)
  if [[ "$DS_COUNT" -gt 0 ]]; then
    RESULT_DSECRETS="FOUND ($DS_COUNT secrets)"
    DETAIL_DSECRETS=$(python3 -c "
import json
d=json.load(open('$DS_OUT'))
count=0
for f,findings in d.get('results',{}).items():
    if count>=3: break
    types=','.join(set(x.get('type','?') for x in findings))
    print('%s (%s)' % (f.replace('$CLONE_DIR/',''), types))
    count+=1
" 2>/dev/null || true)
  else
    RESULT_DSECRETS="CLEAN"
    DETAIL_DSECRETS=""
  fi
else
  RESULT_DSECRETS="SKIPPED (not found)"
  DETAIL_DSECRETS=""
fi

# ── 4. YARA — malware patterns ───────────────────────────────────────────────
echo -e "  ${CYAN}Running YARA...${RESET}"
YARA_RULES="$SCRIPT_DIR/yara-rules.yar"
if command -v yara &>/dev/null && [[ -f "$YARA_RULES" ]]; then
  YARA_OUT=$(yara -r "$YARA_RULES" "$CLONE_DIR" 2>/dev/null \
    | grep -v '\.gitignore$' | grep -v '\.gitattributes$' \
    | grep -v 'README' | grep -v '\.md$' \
    | head -20 || true)
  YARA_COUNT=$(echo "$YARA_OUT" | grep -c . || true)
  if [[ "$YARA_COUNT" -gt 0 ]]; then
    RESULT_YARA="FOUND ($YARA_COUNT matches)"
    DETAIL_YARA=$(echo "$YARA_OUT" | head -3 | sed "s|$CLONE_DIR/||")
  else
    RESULT_YARA="CLEAN"
    DETAIL_YARA=""
  fi
else
  RESULT_YARA="SKIPPED (not found or no rules)"
  DETAIL_YARA=""
fi

# ── 5. Grep — data exfiltration (outbound HTTP calls) ────────────────────────
echo -e "  ${CYAN}Checking exfiltration patterns...${RESET}"
run_grep "EXFIL" '(fetch|axios|requests\.(get|post)|http\.(get|post)|curl)\s*\(?\s*["'"'"']https?://'

# ── 5. Grep — sensitive file/env access ──────────────────────────────────────
echo -e "  ${CYAN}Checking sensitive access patterns...${RESET}"
run_grep "SENS" '(~/\.ssh|~/\.aws|~/\.gnupg|/etc/passwd|/etc/shadow|process\.env\.|os\.environ|getenv\s*\(|localStorage\.(getItem|password|token)|document\.cookie|chrome\.cookies|\.netrc|\.git-credentials)'

# ── 6. Grep — remote code execution ──────────────────────────────────────────
echo -e "  ${CYAN}Checking remote execution patterns...${RESET}"
run_grep "RCE" '(curl.+\|\s*(ba)?sh|wget.+\|\s*(ba)?sh|eval\s*\(.*fetch|eval\s*\(.*http|exec\s*\(.*http)'

# ── 7. Trufflehog — verified secrets with entropy ────────────────────────────
echo -e "  ${CYAN}Running trufflehog...${RESET}"
if command -v trufflehog &>/dev/null; then
  TH_OUT=$(trufflehog filesystem "$CLONE_DIR" --json --no-update 2>/dev/null | head -50 || true)
  TH_COUNT=$(echo "$TH_OUT" | grep -c '"SourceMetadata"' 2>/dev/null || true)
  if [[ "$TH_COUNT" -gt 0 ]]; then
    RESULT_TRUFFLEHOG="FOUND ($TH_COUNT secrets)"
    DETAIL_TRUFFLEHOG=$(echo "$TH_OUT" | python3 -c "
import sys,json
seen=set()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        d=json.loads(line)
        f=d.get('SourceMetadata',{}).get('Data',{}).get('Filesystem',{}).get('file','?')
        det=d.get('DetectorName','?')
        entry='%s (%s)' % (f.replace('$CLONE_DIR/',''),det)
        if entry not in seen:
            seen.add(entry)
            print(entry)
        if len(seen)>=3: break
    except: pass
" 2>/dev/null || true)
  else
    RESULT_TRUFFLEHOG="CLEAN"
    DETAIL_TRUFFLEHOG=""
  fi
else
  RESULT_TRUFFLEHOG="SKIPPED (not found)"
  DETAIL_TRUFFLEHOG=""
fi

# ── 8. Suspicious exfiltration domains ───────────────────────────────────────
echo -e "  ${CYAN}Checking suspicious domains...${RESET}"
run_grep "DOMAINS" '(webhook\.site|discord\.com/api/webhooks|t\.me/|api\.telegram\.org|pastebin\.com|requestbin\.|ngrok\.io|ngrok\.app|burpcollaborator|pipedream\.net|hookbin\.com|canarytokens\.com|interactsh\.com)'

# ── 9. Network syscalls in binaries ──────────────────────────────────────────
echo -e "  ${CYAN}Checking binaries for network syscalls...${RESET}"
BIN_HITS=""
BIN_COUNT=0
while IFS= read -r -d '' bin; do
  if strings "$bin" 2>/dev/null | grep -qE '(connect|socket|send|recv|getaddrinfo|curl_easy_perform|WSAConnect)'; then
    BIN_HITS="$BIN_HITS\n${bin#$CLONE_DIR/}"
    BIN_COUNT=$((BIN_COUNT + 1))
    [[ $BIN_COUNT -ge 3 ]] && break
  fi
done < <(find "$CLONE_DIR" -type f \( -name "*.so" -o -name "*.dylib" -o -name "*.exe" -o -name "*.bin" \) -print0 2>/dev/null)
if [[ $BIN_COUNT -gt 0 ]]; then
  RESULT_BINSYSC="FOUND ($BIN_COUNT binaries)"
  DETAIL_BINSYSC=$(printf '%b' "$BIN_HITS" | sed '/^$/d' | head -3)
else
  RESULT_BINSYSC="CLEAN"
  DETAIL_BINSYSC=""
fi

# ── Report ────────────────────────────────────────────────────────────────────
label_GITLEAKS="Secrets (gitleaks)"
label_SEMGREP="Security audit (semgrep)"
label_DSECRETS="Secrets in code (detect-secrets)"
label_YARA="Malware patterns (yara)"
label_EXFIL="Data exfiltration"
label_SENS="Sensitive file/env access"
label_RCE="Remote code execution"
label_TRUFFLEHOG="Verified secrets (trufflehog)"
label_DOMAINS="Suspicious exfil domains"
label_BINSYSC="Network syscalls in binaries"

CHECKS="GITLEAKS SEMGREP DSECRETS YARA EXFIL SENS RCE TRUFFLEHOG DOMAINS BINSYSC"

echo ""
WIDTH=70
BORDER=$(printf '─%.0s' $(seq 1 $WIDTH))
echo -e "${BOLD}${CYAN}┌${BORDER}┐${RESET}"
printf "${BOLD}${CYAN}│${RESET}  %-36s  %-28s${BOLD}${CYAN}│${RESET}\n" "CHECK" "RESULT"
echo -e "${BOLD}${CYAN}├${BORDER}┤${RESET}"

FOUND_ANY=false
for id in $CHECKS; do
  eval "res=\$RESULT_${id}"
  eval "det=\$DETAIL_${id}"
  eval "lbl=\$label_${id}"

  # Color for result
  if [[ "$res" == "CLEAN" ]]; then
    res_colored="${GREEN}${res}${RESET}"
  elif [[ "$res" == SKIPPED* ]]; then
    res_colored="${YELLOW}${res}${RESET}"
  else
    res_colored="${RED}${res}${RESET}"
    FOUND_ANY=true
  fi

  # Pad label to 36, print result (color doesn't affect layout since it's at end)
  printf "${BOLD}${CYAN}│${RESET}  %-36s  %b" "$lbl" "$res_colored"
  # Fill remaining space to close border
  res_plain=$(echo "$res" | sed 's/\x1b\[[0-9;]*m//g')
  pad=$((WIDTH - 36 - 2 - ${#res_plain} - 2))
  [[ $pad -lt 0 ]] && pad=0
  printf '%*s' "$pad" ""
  echo -e "${BOLD}${CYAN}│${RESET}"

  if [[ -n "$det" ]]; then
    while IFS= read -r line; do
      # Truncate to fit
      line="${line:0:$((WIDTH - 6))}"
      printf "${BOLD}${CYAN}│${RESET}    ${YELLOW}↳${RESET} %-$((WIDTH - 6))s${BOLD}${CYAN}│${RESET}\n" "$line"
    done <<< "$det"
  fi
done

echo -e "${BOLD}${CYAN}└${BORDER}┘${RESET}"
echo -e "  Scanned: ${BOLD}$REPO_URL${RESET}"
echo ""

# ── Save report? ──────────────────────────────────────────────────────────────
read -rp "  Save report as Markdown? [y/N]: " SAVE
if [[ "$SAVE" =~ ^[Yy]$ ]]; then
  REPORT_FILE="$OUT_DIR/${REPO_NAME}-security-report.md"
  {
    echo "# Security Scan Report: \`$REPO_NAME\`"
    echo ""
    echo "> Scanned: $REPO_URL  "
    echo "> Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "## Results"
    echo ""
    echo "| Check | Result | Files |"
    echo "|-------|--------|-------|"
    for id in $CHECKS; do
      eval "res=\$RESULT_${id}"; eval "det=\$DETAIL_${id}"; eval "lbl=\$label_${id}"
      raw_detail=$(echo "$det" | tr '\n' ', ' | sed 's/, $//')
      echo "| $lbl | $res | $raw_detail |"
    done
    echo ""
    if [[ "$FOUND_ANY" == true ]]; then
      echo "## Findings Detail"
      echo ""
      for id in $CHECKS; do
        eval "det=\$DETAIL_${id}"; eval "lbl=\$label_${id}"
        if [[ -n "$det" ]]; then
          echo "### $lbl"
          echo '```'
          echo "$det"
          echo '```'
          echo ""
        fi
      done
    fi
  } > "$REPORT_FILE"
  echo -e "  ${GREEN}Report saved → $REPORT_FILE${RESET}"
fi

echo ""
