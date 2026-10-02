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

check_deps() {
  local missing_brew=""

  for t in $BREW_TOOLS; do
    command -v "$t" &>/dev/null || missing_brew="$missing_brew $t"
  done

  if [[ -n "$missing_brew" ]]; then
    echo -e "${YELLOW}Missing dependencies:${RESET}${missing_brew}"
    if [[ "$NO_INTERACTIVE" == true ]]; then
      echo -e "${YELLOW}  (skipping install in --no-interactive mode)${RESET}"
    else
      read -rp "  Install now? [y/N]: " CONFIRM
      if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        for t in $missing_brew;  do brew install "$t";  done
      fi
    fi
  fi

  if [[ "$CHECK_UPDATES" == true ]] && [[ "$NO_INTERACTIVE" != true ]]; then
    local outdated_brew=""
    for t in $BREW_TOOLS; do
      if command -v "$t" &>/dev/null; then
        [[ $(brew outdated --quiet 2>/dev/null | grep -cx "$t" || true) -gt 0 ]] && outdated_brew="$outdated_brew $t"
      fi
    done
    if [[ -n "$outdated_brew" ]]; then
      echo -e "${YELLOW}Updates available:${RESET}${outdated_brew}"
      read -rp "  Update now? [y/N]: " CONFIRM
      [[ "$CONFIRM" =~ ^[Yy]$ ]] && brew upgrade $outdated_brew
    fi
  fi
}

show_help() {
  cat <<'EOF'
Usage:
  ./repo-scanner.sh [OPTIONS] [REPO_URL_OR_PATH]

Options:
  -r, --repo <url|path>  Repository URL (https/git) or local directory path to scan
  --no-interactive       Skip all prompts; exit code 1 if high-severity findings
  --full-history         Clone full git history and run gitleaks on all commits
  --save                 Automatically save report to out/ without prompting
  --check-updates        Check Homebrew for updates to scanner tools
  -h, --help             Show this help message

Examples:
  ./repo-scanner.sh --repo https://github.com/user/repo
  ./repo-scanner.sh https://github.com/user/repo
  ./repo-scanner.sh --repo .
  ./repo-scanner.sh --repo /path/to/project
  ./repo-scanner.sh --repo https://github.com/user/repo --no-interactive --save
EOF
}

# ── Input ──────────────────────────────────────────────────────────────────────
REPO_URL=""
NO_INTERACTIVE=false
FULL_HISTORY=false
AUTO_SAVE=false
CHECK_UPDATES=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_URL="$2"
      shift 2
      ;;
    --repo=*)
      REPO_URL="${1#*=}"
      shift
      ;;
    -r)
      REPO_URL="$2"
      shift 2
      ;;
    -r=*)
      REPO_URL="${1#*=}"
      shift
      ;;
    --no-interactive)
      NO_INTERACTIVE=true
      shift
      ;;
    --full-history)
      FULL_HISTORY=true
      shift
      ;;
    --save)
      AUTO_SAVE=true
      shift
      ;;
    --check-updates)
      CHECK_UPDATES=true
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    -*)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      show_help >&2
      exit 1
      ;;
    *)
      if [[ -z "$REPO_URL" ]]; then
        REPO_URL="$1"
      fi
      shift
      ;;
  esac
done

check_deps
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║        REPO SECURITY SCANNER             ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${RESET}"
echo ""

if [[ -z "$REPO_URL" ]]; then
  if [[ "$NO_INTERACTIVE" == true ]]; then
    echo "No URL or path provided." && exit 1
  fi
  read -rp "  Repo URL or local path: " REPO_URL
fi
[[ -z "$REPO_URL" ]] && echo "No URL or path provided." && exit 1

IS_LOCAL=false
if [[ "$REPO_URL" == -* ]]; then
  echo -e "${RED}Invalid repo URL or path (must not start with '-'): $REPO_URL${RESET}" >&2
  exit 1
fi
if [[ -d "$REPO_URL" ]]; then
  IS_LOCAL=true
  CLONE_DIR="$(cd "$REPO_URL" && pwd)"
  REPO_NAME="$(basename "$CLONE_DIR")"
  echo -e "  Target: ${BOLD}$CLONE_DIR${RESET} (local directory)"
else
  REPO_NAME=$(basename "$REPO_URL" .git)
  CLONE_DIR="$TMPDIR_SCAN/$REPO_NAME"
  echo -e "  Repo URL: ${BOLD}$REPO_URL${RESET}"
  echo -e "\n  ${CYAN}Cloning...${RESET}"
  if [[ "$FULL_HISTORY" == true ]]; then
    git clone -c core.symlinks=false --quiet -- "$REPO_URL" "$CLONE_DIR" 2>&1 || { echo -e "${RED}Clone failed.${RESET}"; exit 1; }
  else
    git clone -c core.symlinks=false --depth=1 --quiet -- "$REPO_URL" "$CLONE_DIR" 2>&1 || { echo -e "${RED}Clone failed.${RESET}"; exit 1; }
  fi
fi

# ── Check engine ──────────────────────────────────────────────────────────────
# Untrusted-input rules: repo-derived strings are never passed to eval or
# interpolated into code; symlinks, FIFOs and devices are never read.
GREP_EXCLUDES=(
  -D skip
  --exclude="*.test.*" --exclude="*.spec.*"
  --exclude-dir="test" --exclude-dir="tests" --exclude-dir="__tests__"
  --exclude-dir="fixtures" --exclude-dir="testdata" --exclude-dir="spec"
  --exclude-dir="node_modules" --exclude-dir=".git" --exclude-dir=".venv"
  --exclude-dir="venv" --exclude-dir="site-packages")
GREP_INCLUDES=(-rIl
  --include="*.js" --include="*.ts" --include="*.py" --include="*.sh"
  --include="*.env" --include="*.json" --include="*.yml" --include="*.yaml"
  --include="*.rb" --include="*.php" --include="*.go" --include="*.java" --include="*.rs"
  "${GREP_EXCLUDES[@]}")

# Documentation and data files: no code runs from them.
DATA_PATH_RE='(/README$|\.(md|txt|rst|adoc|jsonl|csv|tsv|map)$|\.gitignore$|\.gitattributes$)'
# Vendored dependency trees and VCS metadata.
DEP_PATH_RE='/(node_modules|\.git|\.venv|venv|site-packages)/'
# Test code: skipped by all heuristics unless it is an entry point (conftest.py,
# package.json main/bin, lifecycle targets).
TEST_PATH_RE='(/(test|tests|__tests__|fixtures|testdata|spec)/|\.test\.[A-Za-z0-9]+$|\.spec\.[A-Za-z0-9]+$)'
# Minified bundles: generic heuristics are noise there; high-precision rules still run.
MINIFIED_RE='[.-](min|bundle|umd)\.js$'
# JSON that configures execution (package/MCP/agent/editor/devcontainer).
MANIFEST_JSON_RE='/(package\.json|[^/]*mcp[^/]*\.json|settings\.json|claude_desktop_config\.json|\.vscode/tasks\.json|\.devcontainer/devcontainer\.json|\.devcontainer\.json)$'
# pytest auto-imports conftest.py, so it is never treated as test noise.
AUTOEXEC_RE='/conftest\.py$'

# Newline-delimited set of resolved entry points (filled in below).
ENTRY_SET=$'\n'
ENTRY_FILES=()
LIFECYCLE_TARGETS=()
ENTRY_ERRORS=0

rel_path() { printf '%s' "${1#"$CLONE_DIR"/}"; }

# Strips the clone prefix from every line on stdin (no sed: path is not a regex).
strip_clone_prefix() {
  local line
  while IFS= read -r line; do printf '%s\n' "${line//"$CLONE_DIR"\//}"; done
  return 0
}

# All path predicates take the absolute path; rel is computed inline (no forks).
is_entry_point() {
  [[ "$ENTRY_SET" == *$'\n'"/${1#"$CLONE_DIR"/}"$'\n'* ]]
}

# Data/doc file or vendored tree: skipped by every content check.
is_data_path() {
  local rel="/${1#"$CLONE_DIR"/}"
  is_entry_point "$1" && return 1
  [[ "$rel" =~ $DATA_PATH_RE || "$rel" =~ $DEP_PATH_RE ]] && return 0
  [[ "$rel" == *.json && ! "$rel" =~ $MANIFEST_JSON_RE ]] && return 0
  return 1
}

# Skipped by high-precision rules: data/doc files and vendored trees only.
# Test dirs ARE scanned: code there can be imported by the package (e.g. a
# stealer in tests/util.py imported from pkg/__init__.py).
is_precision_skip() {
  is_data_path "$1"
}

# Skipped by generic heuristics: data paths, test code and minified bundles
# (entry points and conftest.py excepted).
is_noise_path() {
  local rel="/${1#"$CLONE_DIR"/}"
  is_data_path "$1" && return 0
  is_entry_point "$1" && return 1
  [[ "$rel" =~ $AUTOEXEC_RE ]] && return 1
  [[ "$rel" =~ $TEST_PATH_RE || "$rel" =~ $MINIFIED_RE ]] && return 0
  return 1
}

# Reads file paths on stdin and prints only the non-noise ones.
filter_noise() {
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] && ! is_noise_path "$line" && printf '%s\n' "$line"
  done
  return 0
}

# Entry points are grepped directly: tests/ and minified paths are excluded
# from the recursive greps.
grep_entry_points() {
  local pattern="$1"
  [[ ${#ENTRY_FILES[@]} -eq 0 ]] && return 0
  grep -D skip -IlE "$pattern" "${ENTRY_FILES[@]}" 2>/dev/null || true
}

# Counts lines of a file matching $2 but not $3. grep -c reads all input, so
# the upstream grep is never killed by SIGPIPE under pipefail.
count_matches_excluding() {
  local file="$1" pattern="$2" exclude="$3" n
  n=$(grep -ohE "$pattern" "$file" 2>/dev/null | grep -cvE "$exclude" || true)
  printf '%s' "${n:-0}"
}

run_grep() {
  local varname="$1" pattern="$2"
  local hits count detail
  hits=$( { grep -E "${GREP_INCLUDES[@]}" "$pattern" "$CLONE_DIR" 2>/dev/null || true; grep_entry_points "$pattern"; } | sort -u | head -20 || true)
  count=$(printf '%s' "$hits" | grep -c . 2>/dev/null || true)
  if [[ "$count" -gt 0 ]]; then
    detail=$(printf '%s\n' "$hits" | head -3 | strip_clone_prefix)
    printf -v "RESULT_${varname}" '%s' "FOUND ($count files)"
    printf -v "DETAIL_${varname}" '%s' "$detail"
  else
    printf -v "RESULT_${varname}" '%s' "CLEAN"
    printf -v "DETAIL_${varname}" '%s' ""
  fi
}

# ── Entry-point resolution ───────────────────────────────────────────────────
# package.json main/bin and lifecycle-script targets (`node X`, `python X`,
# `npm run X` one level), pyproject [project.scripts], setup.py, conftest.py,
# plus one level of local require()/import from JS entry points. They run on
# install or use, so they are scanned with no noise filter. Each source fails
# open: one malformed manifest never skips the others.
ENTRY_RAW_FILE="$TMPDIR_SCAN/entrypoints.bin"
python3 - "$CLONE_DIR" > "$ENTRY_RAW_FILE" 2>/dev/null <<'PYEOF' || true
import json, os, re, shlex, sys

clone_dir = os.path.realpath(sys.argv[1])
MAX_READ = 1024 * 1024
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "site-packages"}
HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepack", "postpack",
         "preuninstall", "postuninstall")
INTERPRETERS = re.compile(r"^(node|nodejs|python[0-9.]*|sh|bash|zsh|ts-node|tsx|bun|deno)$")
RUNNERS = {"npm", "pnpm", "yarn"}
JS_EXTS = (".js", ".cjs", ".mjs", ".ts")
JS_LOCAL_IMPORT = re.compile(
    r"""(?:require\s*\(\s*|import\s*\(\s*|from\s+|import\s+)["'](\.{1,2}/[^"'\n]+)["']""")
seen = set()

def out(*fields):
    """Write one NUL-terminated record; fields never contain tabs/newlines."""
    sys.stdout.write("\t".join(fields) + "\0")

def emit(kind, base, target):
    """Record an in-repo regular file; returns its path or None."""
    if not isinstance(target, str) or any(c in target for c in "\t\n\r\0"):
        return None
    path = os.path.normpath(os.path.join(base, target))
    real = os.path.realpath(path)
    if not real.startswith(clone_dir + os.sep) or os.path.islink(path) or not os.path.isfile(path):
        return None
    rel = os.path.relpath(real, clone_dir)
    if rel.startswith("..") or any(c in rel for c in "\t\n\r\0"):
        return None
    if (kind, rel) not in seen:
        seen.add((kind, rel))
        out(kind, rel)
    return real

def emit_js(kind, base, target):
    """Emit a JS entry and the local modules it requires/imports (one level)."""
    real = emit(kind, base, target)
    if real is None:
        for ext in JS_EXTS + ("/index.js",):
            real = emit(kind, base, target + ext)
            if real:
                break
    if real is None or not real.endswith(JS_EXTS):
        return
    try:
        for dep in JS_LOCAL_IMPORT.findall(read_text(real)):
            for cand in (dep,) + tuple(dep + ext for ext in JS_EXTS + ("/index.js",)):
                if emit(kind, os.path.dirname(real), cand):
                    break
    except OSError as exc:
        error(real, exc)

def error(path, exc):
    out("error", os.path.relpath(path, clone_dir).replace("\t", " ").replace("\n", " ")[:200])
    print(f"entrypoint parse error: {path}: {exc}", file=sys.stderr)

def read_text(path):
    with open(path, "r", errors="ignore") as fh:
        return fh.read(MAX_READ)

def script_targets(cmd, scripts, depth=0):
    """Yield script files executed by an npm script command."""
    for part in re.split(r"&&|\|\||;|\|", cmd):
        try:
            tokens = shlex.split(part)
        except ValueError:
            tokens = part.split()
        for i, tok in enumerate(tokens):
            name = os.path.basename(tok)
            if name in RUNNERS and depth == 0:
                rest = [t for t in tokens[i + 1:] if t not in ("run", "run-script") and not t.startswith("-")]
                if rest and isinstance(scripts.get(rest[0]), str):
                    yield from script_targets(scripts[rest[0]], scripts, depth + 1)
                break
            if INTERPRETERS.match(name):
                rest = [t for t in tokens[i + 1:] if not t.startswith("-")]
                if rest and "=" not in rest[0]:
                    yield rest[0]
                break
            if tok.startswith("./"):
                yield tok
                break

def module_files(spec):
    """Yield candidate files for a 'pkg.mod:func' console-script spec."""
    mod = spec.split(":")[0].strip().replace(".", "/")
    for root in ("", "src"):
        yield os.path.join(root, mod + ".py")
        yield os.path.join(root, mod, "__init__.py")
        yield os.path.join(root, mod, "__main__.py")

def as_dict(value):
    return value if isinstance(value, dict) else {}

def handle_package_json(root, path):
    data = as_dict(json.loads(read_text(path)))
    sources = [("entry", data.get("main"))]
    bins = data.get("bin")
    sources += [("entry", t) for t in (bins.values() if isinstance(bins, dict) else [bins])]
    scripts = as_dict(data.get("scripts"))
    for hook in HOOKS:
        if isinstance(scripts.get(hook), str):
            sources += [(f"lifecycle:{hook}", t) for t in script_targets(scripts[hook], scripts)]
    for kind, target in sources:
        if isinstance(target, str):
            emit_js(kind, root, target)

def handle_pyproject(root, path):
    try:
        import tomllib
    except ImportError:
        return
    data = as_dict(tomllib.loads(read_text(path)))
    project = as_dict(data.get("project"))
    tables = [project.get("scripts"), project.get("gui-scripts"),
              as_dict(as_dict(data.get("tool")).get("poetry")).get("scripts")]
    for table in tables:
        for spec in as_dict(table).values():
            if isinstance(spec, str):
                for cand in module_files(spec):
                    emit("entry", root, cand)

HANDLERS = {"package.json": handle_package_json, "pyproject.toml": handle_pyproject}
for root, dirs, files in os.walk(clone_dir):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for fname in files:
        path = os.path.join(root, fname)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            if fname in HANDLERS:
                HANDLERS[fname](root, path)
            elif fname in ("setup.py", "conftest.py"):
                emit("entry", root, fname)
        except Exception as exc:  # one malformed manifest must not stop the walk
            error(path, exc)
PYEOF
CLONE_REAL=$(cd "$CLONE_DIR" && pwd -P)
while IFS=$'\t' read -r -d '' kind rel; do
  [[ -z "$rel" ]] && continue
  if [[ "$kind" == "error" ]]; then
    ENTRY_ERRORS=$((ENTRY_ERRORS + 1))
    continue
  fi
  # Defense in depth: only regular files strictly inside the clone
  real=$(cd "$CLONE_DIR" && realpath -- "$rel" 2>/dev/null || true)
  [[ "$real" == "$CLONE_REAL"/* && -f "$real" && ! -L "$CLONE_DIR/$rel" ]] || continue
  if [[ "$ENTRY_SET" != *$'\n'"/$rel"$'\n'* ]]; then
    ENTRY_SET="$ENTRY_SET/$rel"$'\n'
    ENTRY_FILES+=("$CLONE_DIR/$rel")
  fi
  [[ "$kind" == lifecycle:* ]] && LIFECYCLE_TARGETS+=("${kind#lifecycle:}"$'\t'"$rel")
done < "$ENTRY_RAW_FILE"

# ── 1. Gitleaks — secrets & credential theft ──────────────────────────────────
echo -e "  ${CYAN}Running gitleaks...${RESET}"
GITLEAKS_OUT="$TMPDIR_SCAN/gitleaks.json"
if command -v gitleaks &>/dev/null; then
  if [[ "$FULL_HISTORY" == true ]]; then
    gitleaks detect --source "$CLONE_DIR" --report-format json \
      --report-path "$GITLEAKS_OUT" --exit-code 0 -q 2>/dev/null || true
  else
    gitleaks detect --source "$CLONE_DIR" --report-format json \
      --report-path "$GITLEAKS_OUT" --no-git --exit-code 0 -q 2>/dev/null || true
  fi
  GL_COUNT=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$GITLEAKS_OUT" 2>/dev/null || echo 0)
  if [[ "$GL_COUNT" -gt 0 ]]; then
    RESULT_GITLEAKS="FOUND ($GL_COUNT secrets)"
    DETAIL_GITLEAKS=$(python3 - "$GITLEAKS_OUT" "$CLONE_DIR/" 2>/dev/null <<'PYEOF' || true
import json, sys
seen = set()
for item in json.load(open(sys.argv[1]))[:3]:
    line = f"{item.get('File', '?').replace(sys.argv[2], '')} ({item.get('RuleID', '?')})"
    if line not in seen:
        seen.add(line)
        print(line)
PYEOF
)
  else
    RESULT_GITLEAKS="CLEAN"
    DETAIL_GITLEAKS=""
  fi
else
  RESULT_GITLEAKS="SKIPPED (not found)"
  DETAIL_GITLEAKS=""
fi

# ── 2. Semgrep — supply chain malicious patterns ────────────────────────────
echo -e "  ${CYAN}Running semgrep (supply chain)...${RESET}"
SEMGREP_OUT="$TMPDIR_SCAN/semgrep.json"
if command -v semgrep &>/dev/null; then
  semgrep --config "p/supply-chain" \
    --json --output "$SEMGREP_OUT" "$CLONE_DIR" \
    --quiet --no-error 2>/dev/null || true
  SG_COUNT=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("results", [])))' "$SEMGREP_OUT" 2>/dev/null || echo 0)
  if [[ "$SG_COUNT" -gt 0 ]]; then
    RESULT_SEMGREP="FOUND ($SG_COUNT matches)"
    DETAIL_SEMGREP=$(python3 - "$SEMGREP_OUT" "$CLONE_DIR/" 2>/dev/null <<'PYEOF' || true
import json, sys
seen = set()
for res in json.load(open(sys.argv[1])).get("results", [])[:3]:
    line = f"{res.get('path', '?').replace(sys.argv[2], '')} ({res.get('check_id', '?').split('.')[-1]})"
    if line not in seen:
        seen.add(line)
        print(line)
PYEOF
)
  else
    RESULT_SEMGREP="CLEAN"
    DETAIL_SEMGREP=""
  fi
else
  RESULT_SEMGREP="SKIPPED (not found)"
  DETAIL_SEMGREP=""
fi

# ── 3. YARA — malware patterns ───────────────────────────────────────────────
echo -e "  ${CYAN}Running YARA...${RESET}"
YARA_RULES="$SCRIPT_DIR/yara-rules.yar"
YARA_HIGH_PRECISION="CredentialHarvesting SensitiveFileAccess SupplyChainHook RuntimeObfuscation"
YARA_LOW_CONFIDENCE=false
if command -v yara &>/dev/null && [[ -f "$YARA_RULES" ]]; then
  # Exfil endpoints count anywhere. High-precision rules skip only data/doc
  # files and vendored trees (tests and minified bundles ARE scanned). Generic
  # rules also skip tests and minified bundles. Entry points are never skipped. -N: never follow symlinks out of the repo.
  YARA_OUT=$(yara -N -r "$YARA_RULES" "$CLONE_DIR" 2>/dev/null | while IFS= read -r line; do
      rule="${line%% *}"
      path="${line#* }"
      case " $YARA_HIGH_PRECISION " in
        *" $rule "*) is_precision_skip "$path" || printf '%s\n' "$line" ;;
        *) [[ "$rule" == "DataExfiltration" ]] || ! is_noise_path "$path" && printf '%s\n' "$line" ;;
      esac
    done | head -20 || true)
  YARA_COUNT=$(printf '%s' "$YARA_OUT" | grep -c . || true)
  if [[ "$YARA_COUNT" -gt 0 ]]; then
    # Proximity-only matches (decode then exec within 400 bytes) are lower confidence
    if [[ $(printf '%s\n' "$YARA_OUT" | grep -cv '^RuntimeObfuscationSplit ' || true) -eq 0 ]]; then
      YARA_LOW_CONFIDENCE=true
      RESULT_YARA="FOUND ($YARA_COUNT matches, low confidence)"
    else
      RESULT_YARA="FOUND ($YARA_COUNT matches)"
    fi
    DETAIL_YARA=$(printf '%s\n' "$YARA_OUT" | head -3 | strip_clone_prefix)
  else
    RESULT_YARA="CLEAN"
    DETAIL_YARA=""
  fi
else
  RESULT_YARA="SKIPPED (not found or no rules)"
  DETAIL_YARA=""
fi

# ── 4. Grep — sensitive files & AI credentials ──────────────────────────────
echo -e "  ${CYAN}Checking sensitive files & AI credentials...${RESET}"
# Only credential material counts: private keys, credential/token stores, and
# bulk environment dumps. Reading a single config env var or an app's own
# config dir (~/.codex/config.toml, ~/.ssh/<app>_key) is normal behavior.
Q="[\"']"
SENS_PATTERN="(\.ssh/id_[A-Za-z0-9_]+(\.pub)?|${Q}id_(rsa|ed25519|ecdsa|dsa)${Q}|\.aws/credentials|${Q}\.aws${Q}\s*[,/]\s*${Q}credentials${Q}|\.claude/\.credentials\.json|\.codex/auth\.json|\.config/gh/hosts\.yml|state\.vscdb|\.gnupg/(private-keys|secring)|\.git-credentials|[^.]/etc/shadow|chrome\.cookies|keytar\.(getPassword|findCredentials)|[\"'/~]\.netrc\b|(~|\\\$HOME|\\\$\{HOME\}|%USERPROFILE%)[/\\\\]\.(npmrc|pypirc|docker/config\.json)|(homedir\(\)|Path\.home\(\)).{0,40}${Q}\.(npmrc|pypirc|netrc)${Q}|JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\([^)]*os\.environ)"
# Candidates for the proximity checks below (authorized_keys, .ssh, env dumps)
SENS_PROX_PATTERN='(authorized_keys|\.ssh\b|process\.env|os\.environ)'
SENS_HITS=$'\n'
SENS_COUNT=0
add_sens_hit() {
  local rel
  rel=$(rel_path "$1")
  [[ "$SENS_HITS" == *$'\n'"$rel"$'\n'* ]] && return 0
  SENS_HITS="$SENS_HITS$rel"$'\n'
  SENS_COUNT=$((SENS_COUNT + 1))
}
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  # Public keys (*.pub) are not secrets
  if [[ $(count_matches_excluding "$file" "$SENS_PATTERN" '\.pub$') -gt 0 ]]; then
    add_sens_hit "$file"
  fi
done < <({ grep -rIEl "${GREP_INCLUDES[@]:1}" "$SENS_PATTERN" "$CLONE_DIR" 2>/dev/null | filter_noise | head -20 || true; grep_entry_points "$SENS_PATTERN"; } | sort -u)
# Proximity checks (multi-line, capped reads): authorized_keys written next to
# a hardcoded key or a network fetch, ~/.ssh enumeration, env dump near a sink.
SENS_PROX=$( { grep -rIEl "${GREP_INCLUDES[@]:1}" "$SENS_PROX_PATTERN" "$CLONE_DIR" 2>/dev/null | filter_noise | head -50 || true; grep_entry_points "$SENS_PROX_PATTERN"; } | sort -u | python3 -c '
import os, re, sys

MAX_READ = 2 * 1024 * 1024
WINDOW = 400
KEY_LITERAL = re.compile(r"ssh-(rsa|ed25519|dss|ecdsa-sha2-nistp[0-9]+) AAAA[0-9A-Za-z+/]{20,}")
NET_FETCH = re.compile(r"\b(curl|wget)\s|urlopen\(|requests\.get\(|httpx\.get\(|\bfetch\(|https?://[^\s\"]+\.keys\b")
SSH_ENUM = re.compile(
    r"(listdir|scandir|readdirSync|readdir|glob|walk|iterdir|rglob)\s*\([^\n]{0,80}[\"'"'"'/]\.ssh\b"
    r"|[\"'"'"'/]\.ssh[\"'"'"'/)][^\n]{0,80}\.(iterdir|glob|rglob)\(")
ENV_DUMP = re.compile(
    r"\.\.\.process\.env\b|Object\.(entries|keys|values)\(process\.env\)"
    r"|JSON\.stringify\([^)]{0,40}process\.env|(dict|str)\(os\.environ\)|os\.environ\.copy\(\)"
    r"|environ\.items\(\)")
NET_SINK = re.compile(
    r"\bfetch\s*\(|axios\.(post|put)|https?\.request\(|XMLHttpRequest|sendBeacon"
    r"|requests\.(post|put)\(|httpx\.(post|put)\(|urlopen\(")

def near(text, first, second):
    """True if a match of second lies within WINDOW bytes of a match of first."""
    for m in first.finditer(text):
        if second.search(text, max(0, m.start() - WINDOW), m.end() + WINDOW):
            return True
    return False

AUTH = re.compile(r"authorized_keys")
for path in (line.rstrip("\n") for line in sys.stdin):
    if not path or os.path.islink(path) or not os.path.isfile(path):
        continue
    try:
        with open(path, "r", errors="ignore") as fh:
            text = fh.read(MAX_READ)
    except OSError:
        continue  # unreadable file: nothing to analyse
    if (AUTH.search(text) and (KEY_LITERAL.search(text) or near(text, AUTH, NET_FETCH))) \
            or SSH_ENUM.search(text) or near(text, ENV_DUMP, NET_SINK):
        print(path)
' 2>/dev/null || true)
while IFS= read -r file; do
  [[ -n "$file" ]] && add_sens_hit "$file"
done <<< "$SENS_PROX"
if [[ "$SENS_COUNT" -gt 0 ]]; then
  RESULT_SENS="FOUND ($SENS_COUNT files)"
  DETAIL_SENS=$(printf '%s' "$SENS_HITS" | sed '/^$/d' | head -3)
else
  RESULT_SENS="CLEAN"
  DETAIL_SENS=""
fi

# ── 6. Grep — remote code execution ──────────────────────────────────────────
echo -e "  ${CYAN}Checking remote execution patterns...${RESET}"
RCE_HITS=$'\n'
add_rce_hit() {
  local rel
  rel=$(rel_path "$1")
  [[ "$RCE_HITS" == *$'\n'"$rel"$'\n'* ]] || RCE_HITS="$RCE_HITS$rel"$'\n'
}
# In shell scripts: download piped into a shell/sudo shell/stdin python,
# process substitution, or sh -c "$(curl ...)". Comment lines and lines that
# only echo/printf one quoted string (install hints) are ignored.
SHELL_RCE_PATTERN='((curl|wget).+\|\s*(sudo\s+(-[A-Za-z]+\s+)*)?((ba|z)?sh\b|python[0-9.]*\s*(-\s*)?($|[;&|)]))|(ba|z)?sh\s+<\(\s*(curl|wget)|(ba|z)?sh\s+-c\s+["'"'"']?\$\(\s*(curl|wget))'
SHELL_HINT_LINE='^\s*(#|(echo|printf)\s+("[^"]*"|'"'"'[^'"'"']*'"'"')\s*$)'
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  if [[ $(grep -E "$SHELL_RCE_PATTERN" "$file" 2>/dev/null | grep -cvE "$SHELL_HINT_LINE" || true) -gt 0 ]]; then
    add_rce_hit "$file"
  fi
done < <({ grep -rIlE --include="*.sh" "${GREP_EXCLUDES[@]}" "$SHELL_RCE_PATTERN" "$CLONE_DIR" 2>/dev/null | filter_noise | head -10 || true; grep_entry_points "$SHELL_RCE_PATTERN"; } | sort -u)

# In code files, the decoded/downloaded payload must be the argument of the
# exec/eval call itself, or a curl|sh pipeline must be inside a process call
CODE_INCLUDES=(-rIEl
  --include="*.js" --include="*.mjs" --include="*.cjs" --include="*.ts" --include="*.py"
  --include="*.rb" --include="*.php" --include="*.go" --include="*.java" --include="*.rs"
  "${GREP_EXCLUDES[@]}")
RCE_CODE_PATTERN='(\b(exec|eval)\s*\(\s*(await\s+)?[A-Za-z0-9_.]*(__import__\(.base64.\)\.)?[A-Za-z0-9_.]*(b64decode|b32decode|b85decode|a85decode|fromhex|decompress|urlopen|requests\.get|fetch|atob|Buffer\.from|axios\.get|marshal\.loads)\s*\(|\b(exec|execSync|spawn|spawnSync|execFile|system|popen|Popen|run|call|check_output)\s*\([^)]{0,200}(curl|wget)[^)]{0,200}\|\s*(ba|z)?sh\b)'
while IFS= read -r file; do
  [[ -n "$file" ]] && add_rce_hit "$file"
done < <({ grep "${CODE_INCLUDES[@]}" "$RCE_CODE_PATTERN" "$CLONE_DIR" 2>/dev/null | filter_noise | head -10 || true; grep_entry_points "$RCE_CODE_PATTERN"; } | sort -u)

RCE_COUNT=$(printf '%s' "$RCE_HITS" | grep -c . || true)
if [[ "$RCE_COUNT" -gt 0 ]]; then
  RESULT_RCE="FOUND ($RCE_COUNT files)"
  DETAIL_RCE=$(printf '%s' "$RCE_HITS" | sed '/^$/d' | head -3)
else
  RESULT_RCE="CLEAN"
  DETAIL_RCE=""
fi

# ── 7. Trufflehog — verified secrets with entropy ────────────────────────────
echo -e "  ${CYAN}Running trufflehog...${RESET}"
if command -v trufflehog &>/dev/null; then
  TH_OUT=$(trufflehog filesystem "$CLONE_DIR" --json --only-verified --no-update 2>/dev/null | head -50 || true)
  TH_PARSED=$(printf '%s\n' "$TH_OUT" | python3 -c '
import json, sys
prefix = sys.argv[1]
findings = []
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        item = json.loads(raw)
    except ValueError:
        continue  # non-JSON log line from trufflehog
    if item.get("Verified", False):
        fpath = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "?")
        findings.append((fpath.replace(prefix, ""), item.get("DetectorName", "?")))
print(len(findings))
seen = set()
for fpath, det in findings:
    entry = f"{fpath} ({det})"
    if entry not in seen:
        seen.add(entry)
        print(entry)
    if len(seen) >= 3:
        break
' "$CLONE_DIR/" 2>/dev/null || true)
  TH_COUNT=$(echo "$TH_PARSED" | head -1)
  [[ -z "$TH_COUNT" ]] && TH_COUNT=0
  if [[ "$TH_COUNT" -gt 0 ]]; then
    RESULT_TRUFFLEHOG="FOUND ($TH_COUNT secrets)"
    DETAIL_TRUFFLEHOG=$(echo "$TH_PARSED" | tail -n +2)
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
run_grep "DOMAINS" '(webhook\.site|discord\.com/api/webhooks|(^|[^A-Za-z0-9.-])t\.me/|api\.telegram\.org|pastebin\.com|requestbin\.|ngrok\.io|ngrok\.app|burpcollaborator|pipedream\.net|hookbin\.com|canarytokens\.com|interactsh\.com)'

# ── 9. Network syscalls in binaries ──────────────────────────────────────────
echo -e "  ${CYAN}Checking binaries for network syscalls...${RESET}"
BIN_HITS=""
BIN_COUNT=0
while IFS= read -r -d '' bin; do
  # Exact symbol names only; substrings like "send" match almost any binary
  # grep -c reads all of strings' output (grep -q would SIGPIPE it under pipefail)
  if [[ $(strings "$bin" 2>/dev/null | grep -cE '^_?(connect|socket|getaddrinfo|curl_easy_perform|WSAConnect|InternetOpen(Url)?[AW]?|HttpSendRequest(Ex)?[AW]?|WinHttpOpen|WinHttpConnect|URLDownloadToFile[AW]?)$' || true) -gt 0 ]]; then
    BIN_HITS="$BIN_HITS"$'\n'"$(rel_path "$bin")"
    BIN_COUNT=$((BIN_COUNT + 1))
    [[ $BIN_COUNT -ge 3 ]] && break
  fi
done < <(find "$CLONE_DIR" -type f \( -name "*.so" -o -name "*.dylib" -o -name "*.exe" -o -name "*.bin" \) -print0 2>/dev/null)
if [[ $BIN_COUNT -gt 0 ]]; then
  RESULT_BINSYSC="FOUND ($BIN_COUNT binaries)"
  DETAIL_BINSYSC=$(printf '%s' "$BIN_HITS" | sed '/^$/d' | head -3)
else
  RESULT_BINSYSC="CLEAN"
  DETAIL_BINSYSC=""
fi

# ── 10. Committed .env files ──────────────────────────────────────────────────
echo -e "  ${CYAN}Checking for committed .env files...${RESET}"
ENV_HITS=$(find "$CLONE_DIR" -type f \( -name ".env" -o -name ".env.local" -o -name ".env.production" -o -name ".env.staging" -o -name ".env.development" \) 2>/dev/null | head -10 || true)
ENV_COUNT=$(echo "$ENV_HITS" | grep -c . 2>/dev/null || true)
if [[ "$ENV_COUNT" -gt 0 ]]; then
  RESULT_ENVFILES="FOUND ($ENV_COUNT files)"
  DETAIL_ENVFILES=$(printf '%s\n' "$ENV_HITS" | head -3 | strip_clone_prefix)
else
  RESULT_ENVFILES="CLEAN"
  DETAIL_ENVFILES=""
fi

# ── 11. Lifecycle script analysis ────────────────────────────────────────────
echo -e "  ${CYAN}Checking lifecycle scripts...${RESET}"
LIFECYCLE_HITS=""
LIFECYCLE_COUNT=0
add_lifecycle_hit() {
  LIFECYCLE_HITS="$LIFECYCLE_HITS$1"$'\n'
  LIFECYCLE_COUNT=$((LIFECYCLE_COUNT + 1))
}
while IFS= read -r -d '' pkgjson; do
  is_data_path "$pkgjson" && continue
  suspicious=$(python3 - "$pkgjson" "$(rel_path "$pkgjson")" 2>/dev/null <<'PYEOF2'
import json, sys
MAX_READ = 1024 * 1024
try:
    with open(sys.argv[1], "r", errors="ignore") as fh:
        data = json.loads(fh.read(MAX_READ))
    scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
except (OSError, ValueError, RecursionError) as exc:
    print(f"package.json parse skipped: {exc}", file=sys.stderr)
    scripts = {}
dangerous = ["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"]
exec_patterns = ["curl", "wget", "node -e", "python -c", "bash -c", "sh -c", "exec(", "eval(",
                 "powershell", "Invoke-WebRequest", "iwr "]
for hook in dangerous:
    cmd = str(scripts.get(hook, "")) if isinstance(scripts, dict) else ""
    if any(p in cmd for p in exec_patterns):
        print(f"{sys.argv[2]}: {hook}: {cmd[:80]}")
PYEOF2
) || true
  [[ -n "$suspicious" ]] && add_lifecycle_hit "$suspicious"
done < <(find "$CLONE_DIR" -type f -name "package.json" -not -path "*/node_modules/*" -not -path "*/.git/*" -print0 2>/dev/null)

# Script files run by lifecycle hooks (`node scripts/x.js`, `python x.py`) are
# install-time code regardless of their name (x.min.js, tests/...): flag them
# when they match a high-precision rule or the RCE/credential patterns.
for entry in "${LIFECYCLE_TARGETS[@]+"${LIFECYCLE_TARGETS[@]}"}"; do
  hook="${entry%%$'\t'*}"
  target="${entry#*$'\t'}"
  reason=""
  if command -v yara &>/dev/null && [[ -f "$YARA_RULES" ]]; then
    reason=$(yara -N "$YARA_RULES" "$CLONE_DIR/$target" 2>/dev/null | awk '$1 != "RuntimeObfuscationSplit" {print $1}' | head -1 || true)
  fi
  if [[ -z "$reason" ]]; then
    for pat in "$RCE_CODE_PATTERN" "$SHELL_RCE_PATTERN" "$SENS_PATTERN"; do
      if grep -qE "$pat" "$CLONE_DIR/$target" 2>/dev/null; then
        reason="exec/credential pattern"
        break
      fi
    done
  fi
  [[ -n "$reason" ]] && add_lifecycle_hit "$hook runs $target ($reason)"
done

# setup.py runs at install time: flag network access or dynamic code execution,
# subprocesses that launch interpreters/downloaders, and subprocesses inside
# install/develop/egg_info command classes. Build tools (cmake, ninja, pip,
# sys.executable for builds) are normal.
while IFS= read -r -d '' setuppy; do
  is_data_path "$setuppy" && continue
  reason=$(python3 - "$setuppy" 2>/dev/null <<'PYEOF3'
import ast, re, sys

MAX_READ = 1024 * 1024
NET_OR_EXEC = re.compile(
    r"urlopen|urllib\.request|requests\.(get|post)|http\.client|\bsocket\.|\bcurl\b|\bwget\b"
    r"|os\.system\s*\(|os\.popen\s*\(|__import__\s*\(|\bpowershell\b|Invoke-WebRequest")
EXEC_CALL = re.compile(r"(^|[^A-Za-z0-9_.])(exec|eval)\s*\(")
# exec(open("pkg/version.py").read()) / exec(fp.read(), about): version-file idiom
LOCAL_READ_ARG = re.compile(
    r"\s*(open\s*\([^)]*\)\s*\.\s*read\s*\(|[A-Za-z_][A-Za-z0-9_]*\.read\s*\("
    r"|[A-Za-z_][A-Za-z0-9_.()\"' /]*\.read_text\s*\(|compile\s*\(\s*open\s*\()")
SPAWN = re.compile(r"(subprocess\.[A-Za-z_]+|os\.spawn[a-z]*|Popen)\s*\(")
LAUNCHER_ARGS = re.compile(
    r"powershell|pwsh|cmd(\.exe)?[\"' ]|[\"'](ba|z)?sh[\"']|[\"']-c[\"']|\biwr\b|certutil|mshta|curl|wget")
BUILD_TOOLS = re.compile(r"\b(cmake|ninja|pip|make|meson)\b")
HOOK_BASES = {"install", "develop", "egg_info", "_install", "_develop", "install_lib",
              "install_scripts"}

with open(sys.argv[1], "r", errors="ignore") as fh:
    source = fh.read(MAX_READ)
code = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))

def call_text(start):
    """Return a spawn call's text up to its closing paren (bounded)."""
    depth, end = 0, start
    for end in range(start, min(len(code), start + 400)):
        depth += {"(": 1, ")": -1}.get(code[end], 0)
        if depth == 0 and code[end] == ")":
            break
    return code[start:end + 1]

def hook_classes(tree):
    """Names of classes used as install/develop/egg_info commands."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {getattr(b, "id", getattr(b, "attr", "")) for b in node.bases}
            if bases & HOOK_BASES:
                names.add(node.name)
        if isinstance(node, ast.Dict):
            for key, val in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in HOOK_BASES and isinstance(val, ast.Name):
                    names.add(val.id)
    return names

def spawns_in_hooks():
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return False
    hooks = hook_classes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in hooks:
            seg = ast.get_source_segment(source, node) or ""
            for m in SPAWN.finditer(seg):
                if not BUILD_TOOLS.search(seg[m.start():m.start() + 300]):
                    return True
    return False

def dynamic_exec():
    """exec/eval whose argument is not a plain local file read."""
    for m in EXEC_CALL.finditer(code):
        paren = code.index("(", m.end() - 1)
        if not LOCAL_READ_ARG.match(code, paren + 1):
            return True
    return False

if NET_OR_EXEC.search(code):
    print("network access at install time")
elif dynamic_exec():
    print("dynamic exec at install time")
elif any(LAUNCHER_ARGS.search(call_text(m.start())) for m in SPAWN.finditer(code)):
    print("subprocess launches an interpreter or downloader")
elif spawns_in_hooks():
    print("subprocess inside install/develop/egg_info command")
PYEOF3
) || true
  [[ -n "$reason" ]] && add_lifecycle_hit "$(rel_path "$setuppy") ($reason)"
done < <(find "$CLONE_DIR" -type f -name "setup.py" -not -path "*/node_modules/*" -not -path "*/.git/*" -print0 2>/dev/null)
if [[ "$LIFECYCLE_COUNT" -gt 0 ]]; then
  RESULT_LIFECYCLE="FOUND ($LIFECYCLE_COUNT files)"
  DETAIL_LIFECYCLE=$(printf '%s' "$LIFECYCLE_HITS" | sed '/^$/d' | head -3)
elif [[ "$ENTRY_ERRORS" -gt 0 ]]; then
  # Unparseable manifests: entry points may be missing, so never report CLEAN
  RESULT_LIFECYCLE="WARN ($ENTRY_ERRORS manifests unparsed)"
  DETAIL_LIFECYCLE=$(tr '\0' '\n' < "$ENTRY_RAW_FILE" | sed -n $'s/^error\t//p' | head -3)
else
  RESULT_LIFECYCLE="CLEAN"
  DETAIL_LIFECYCLE=""
fi

# ── 12. Typosquatting detection ───────────────────────────────────────────────
echo -e "  ${CYAN}Checking for typosquatting...${RESET}"
TYPO_HITS=$(python3 - "$CLONE_DIR" 2>/dev/null <<'PYEOF'
import sys, json, os, re

POPULAR_NPM = [
    "react","lodash","express","axios","moment","chalk","commander","dotenv",
    "webpack","babel","typescript","eslint","prettier","jest","mocha","request",
    "async","underscore","uuid","debug","colors","yargs","minimist","semver",
    "glob","mkdirp","rimraf","cross-env","nodemon","pm2","socket.io","mongoose",
    "sequelize","passport","jsonwebtoken","bcrypt","cors","helmet","morgan",
    "body-parser","multer","sharp","cheerio","puppeteer","playwright","selenium"
]
POPULAR_PY = [
    "requests","numpy","pandas","flask","django","fastapi","sqlalchemy","celery",
    "boto3","pytest","setuptools","pip","wheel","cryptography","paramiko","fabric",
    "click","pydantic","httpx","aiohttp","beautifulsoup4","scrapy","pillow",
    "matplotlib","scipy","sklearn","tensorflow","torch","transformers","openai"
]

# Real packages that sit one edit away from a popular name
LEGIT_NEIGHBORS = {"preact", "color", "scapy", "boto", "torchx", "yarn", "redux"}
MIN_LEN = 5

def levenshtein(a, b):
    """Optimal string alignment distance: edits plus adjacent transpositions."""
    if abs(len(a)-len(b)) > 2: return 99
    d = [[i + j if i * j == 0 else 0 for j in range(len(b)+1)] for i in range(len(a)+1)]
    for i in range(1, len(a)+1):
        for j in range(1, len(b)+1):
            d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+(a[i-1] != b[j-1]))
            if i > 1 and j > 1 and a[i-1] == b[j-2] and a[i-2] == b[j-1]:
                d[i][j] = min(d[i][j], d[i-2][j-2]+1)
    return d[-1][-1]

def norm(name):
    return name.lower().replace('_', '-').replace('.', '-')

def check(rel, eco, pkg, popular):
    n = norm(pkg)
    if len(n) < MIN_LEN or n in LEGIT_NEIGHBORS:
        return
    for pop in popular:
        if 0 < levenshtein(n, norm(pop)) <= 1:
            findings.append('%s: %s "%s" ~ "%s"' % (rel, eco, pkg, pop))
            return

REQ_NAME = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)')

def req_name(spec):
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    if not spec or spec.startswith(('#', '-', 'git+', 'http:', 'https:', 'file:')):
        return None
    m = REQ_NAME.match(spec)
    return m.group(1) if m else None

MAX_READ = 1024 * 1024
# install_requires list; tolerates extras such as "requests[socks]"
INSTALL_REQUIRES = re.compile(r'install_requires\s*=\s*\[((?:[^\[\]]|\[[^\[\]]*\])*)\]', re.S)

def read_text(path):
    with open(path, 'r', errors='ignore') as fh:
        return fh.read(MAX_READ)

def load_toml(content):
    try:
        import tomllib
    except ImportError:
        return {}
    return tomllib.loads(content)

def python_deps(path, fname):
    content = read_text(path)
    if fname == 'requirements.txt':
        return [req_name(l) for l in content.splitlines()]
    if fname == 'Pipfile':
        data = load_toml(content)
        return [k for sec in ('packages', 'dev-packages')
                for k in (data.get(sec) if isinstance(data.get(sec), dict) else {})]
    if fname == 'pyproject.toml':
        data = load_toml(content)
        specs = list(data.get('project', {}).get('dependencies', []))
        for group in data.get('project', {}).get('optional-dependencies', {}).values():
            specs.extend(group)
        poetry = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
        specs.extend(k for k in poetry if k.lower() != 'python')
        return [req_name(s) for s in specs]
    if fname == 'setup.py':
        m = INSTALL_REQUIRES.search(content)
        if not m:
            return []
        return [req_name(s) for s in re.findall(r'["\']([^"\']+)["\']', m.group(1))]
    return []

clone_dir = sys.argv[1]
findings = []
SKIP_DIRS = {'node_modules', '.git', '.venv', 'venv', 'site-packages'}

for root, dirs, files in os.walk(clone_dir):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for fname in files:
        path = os.path.join(root, fname)
        rel = path.replace(clone_dir + '/', '')
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            if fname == 'package.json':
                d = json.loads(read_text(path))
                d = d if isinstance(d, dict) else {}
                deps = {}
                for section in ('dependencies', 'devDependencies'):
                    if isinstance(d.get(section), dict):
                        deps.update(d[section])
                for pkg in deps:
                    # Scoped packages are owned by the scope, not typosquat-prone
                    if not pkg.startswith('@'):
                        check(rel, 'npm', pkg, POPULAR_NPM)
            elif fname in ('requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile'):
                for pkg in python_deps(path, fname):
                    if pkg:
                        check(rel, 'pip', pkg, POPULAR_PY)
        except Exception as exc:  # one malformed manifest must not stop the walk
            print(f"typosquat parse skipped: {rel}: {exc}", file=sys.stderr)

for f in findings[:10]:
    print(f)
PYEOF
) || TYPO_ERR=true
TYPO_COUNT=$(echo "$TYPO_HITS" | grep -c . 2>/dev/null || true)
if [[ "$TYPO_COUNT" -gt 0 ]]; then
  RESULT_TYPOSQUAT="FOUND ($TYPO_COUNT suspects)"
  DETAIL_TYPOSQUAT=$(echo "$TYPO_HITS" | head -3)
elif [[ "${TYPO_ERR:-false}" == true ]]; then
  RESULT_TYPOSQUAT="SKIPPED (error)"
  DETAIL_TYPOSQUAT=""
else
  RESULT_TYPOSQUAT="CLEAN"
  DETAIL_TYPOSQUAT=""
fi

# ── 12. MCP & agent tool configurations ──────────────────────────────────────
echo -e "  ${CYAN}Checking MCP & agent configurations...${RESET}"
MCP_HITS=$(python3 - "$CLONE_DIR" 2>/dev/null <<'PYEOF'
import sys, json, os, re

clone_dir = sys.argv[1]
findings = []

RUNNERS = ('npx', 'uvx', 'bunx', 'pnpx')
MAX_READ = 1024 * 1024

def unpinned_package(cmd, args):
    """Return the package a runner (npx/uvx) would fetch without a version pin."""
    tokens = [os.path.basename(cmd)] + [str(a) for a in args]
    for i, tok in enumerate(tokens):
        if tok not in RUNNERS:
            continue
        rest = tokens[i + 1:]
        for j, arg in enumerate(rest):
            if arg == '--from' and j + 1 < len(rest):
                pkg = rest[j + 1]
                break
            if not arg.startswith('-'):
                pkg = arg
                break
        else:
            return None
        # Pinned: name@1.2.3 / @scope/name@1.2.3 / name==1.2.3
        if re.search(r'(?<!^)@\d|==\d', pkg):
            return None
        return pkg
    return None

for root, dirs, files in os.walk(clone_dir):
    dirs[:] = [d for d in dirs if d not in ('node_modules', '.git')]
    for fname in files:
        if not (fname.endswith('mcp.json') or fname in ('claude_desktop_config.json', 'settings.json')):
            continue
        fpath = os.path.join(root, fname)
        rel = fpath.replace(clone_dir + '/', '')
        if os.path.islink(fpath) or not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', errors='ignore') as fh:
                d = json.loads(fh.read(MAX_READ))
            if not isinstance(d, dict): continue
            servers = d.get('mcpServers', {})
            if not isinstance(servers, dict) and 'mcp' in d and isinstance(d['mcp'], dict):
                servers = d['mcp'].get('mcpServers', {})
            if not isinstance(servers, dict): continue

            for name, srv in servers.items():
                if not isinstance(srv, dict): continue
                cmd = str(srv.get('command', '')).strip()
                args_list = srv.get('args', [])
                args_str = ' '.join(str(a) for a in args_list) if isinstance(args_list, list) else str(args_list)
                full = f"{cmd} {args_str}".strip()
                reasons = []
                if any(sh == cmd or cmd.endswith('/' + sh) for sh in ['bash', 'sh', 'zsh', 'cmd.exe', 'powershell', 'pwsh']):
                    reasons.append('shell wrapper')
                pkg = unpinned_package(cmd, args_list if isinstance(args_list, list) else str(args_list).split())
                if pkg:
                    reasons.append(f'unpinned remote package execution: {pkg}')
                if re.search(r'\b(curl|wget|ngrok|nc|ncat)\b|eval\(|exec\(', full):
                    reasons.append('remote download/tunneling pattern')
                if reasons:
                    findings.append(f"{rel}: {name} ({', '.join(reasons)})")
        except Exception as exc:  # one malformed config must not stop the walk
            print(f"MCP config parse skipped: {rel}: {exc}", file=sys.stderr)

for f in findings[:10]:
    print(f)
PYEOF
) || MCP_ERR=true
MCP_COUNT=$(echo "$MCP_HITS" | grep -c . 2>/dev/null || true)
if [[ "$MCP_COUNT" -gt 0 ]]; then
  RESULT_MCPCONFIG="FOUND ($MCP_COUNT tools)"
  DETAIL_MCPCONFIG=$(echo "$MCP_HITS" | head -3)
elif [[ "${MCP_ERR:-false}" == true ]]; then
  RESULT_MCPCONFIG="SKIPPED (error)"
  DETAIL_MCPCONFIG=""
else
  RESULT_MCPCONFIG="CLEAN"
  DETAIL_MCPCONFIG=""
fi

# ── 13. Python .pth & unsafe serialization ───────────────────────────────────
echo -e "  ${CYAN}Checking Python .pth & serialization payloads...${RESET}"
PTH_HITS=$(python3 - "$CLONE_DIR" 2>/dev/null <<'PYEOF'
import io, os, pickletools, re, struct, sys, zipfile, zlib

clone_dir = sys.argv[1]
findings = []

# Allowlist (picklescan/fickling style): every imported (module, name) must be
# here, per name. torch mirrors torch.load(weights_only=True): rebuild helpers,
# storages, dtypes and nn module classes only; any other torch name is a gadget
# (e.g. torch.utils.collect_env.run is Popen(shell=True)). Non-allowlisted
# stdlib names and known gadget roots are "dangerous" (high severity); unknown
# third-party names are "suspicious".
TRUSTED_ROOTS = {"torch"}
TORCH_SAFE = re.compile(
    r"^torch\._utils\._rebuild_[a-z0-9_]+$"
    r"|^torch\._tensor\._rebuild_from_type(_v2)?$"
    r"|^torch\.[A-Za-z]*Storage$|^torch\.storage\.(TypedStorage|UntypedStorage)$"
    r"|^torch\.(Size|device|dtype|layout|memory_format|Tensor|strided|sparse_coo|channels_last|contiguous_format|preserve_format)$"
    r"|^torch\.(float|double|half|bfloat16|int|long|short|bool|uint8|int8|int16|int32|int64|float16|float32|float64|complex64|complex128|cfloat|cdouble)$"
    r"|^torch\.nn\.parameter\.(Parameter|Buffer)$"
    r"|^torch\.nn\.modules\.[a-z_.]+\.[A-Z][A-Za-z0-9]*$")
SAFE_GLOBALS = {
    "collections.OrderedDict", "collections.defaultdict", "collections.deque",
    "collections.Counter", "_codecs.encode", "codecs.encode", "copyreg._reconstructor",
    "copy_reg._reconstructor", "datetime.datetime", "datetime.date", "datetime.time",
    "datetime.timedelta", "datetime.timezone", "decimal.Decimal", "fractions.Fraction",
    "uuid.UUID", "pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath",
    "pathlib.PurePosixPath", "pathlib.PureWindowsPath", "argparse.Namespace",
    "functools.partial", "types.SimpleNamespace", "array.array", "array._array_reconstructor",
    "re._compile", "enum.Enum",
    "numpy.core.multiarray._reconstruct", "numpy.core.multiarray.scalar",
    "numpy._core.multiarray._reconstruct", "numpy._core.multiarray.scalar",
    "numpy.core.numeric._frombuffer", "numpy._core.numeric._frombuffer",
    "numpy.dtype", "numpy.ndarray", "numpy.ma.core._mareconstruct",
    "numpy.random._pickle.__randomstate_ctor", "numpy.random._pickle.__generator_ctor",
    "numpy.random._pickle.__bit_generator_ctor",
}
NUMPY_SCALAR = re.compile(r"^numpy\.(float|int|uint|complex)(8|16|32|64|128)?$|^numpy\.bool_?$")
BUILTINS_SAFE = {"set", "frozenset", "slice", "range", "complex", "bytearray", "bytes",
                 "object", "int", "float", "str", "list", "dict", "tuple", "bool",
                 "Ellipsis", "NotImplemented"}
DENY_PREFIXES = ("torch.hub", "torch.load", "torch.jit", "torch.utils.cpp_extension",
                 "torch.package", "torch.serialization.load", "torch._C._jit",
                 "torch.ops", "torch._ops", "torch.utils.data.datapipes")
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__builtin__", "copy_reg", "cPickle", "commands"}
# Known code-execution / I/O / network gadgets (labelled "dangerous")
DANGEROUS_ROOTS = {"os", "posix", "nt", "pty", "socket", "runpy", "commands", "importlib",
                   "marshal", "ctypes", "shutil", "webbrowser", "code", "codeop",
                   "multiprocessing", "urllib", "requests", "http", "ftplib", "smtplib",
                   "telnetlib", "sys", "asyncio", "pip", "dill", "timeit", "cProfile", "profile",
                   "pydoc", "trace", "bdb", "pdb", "doctest", "cPickle", "pickle", "_pickle",
                   "_io", "io", "tempfile", "glob", "zipimport", "_osx_support", "distutils",
                   "setuptools"}
RISKY_NAMES = {"system", "popen", "exec", "eval", "compile", "__import__", "getattr",
               "open", "spawn", "run", "call", "Popen", "loads", "load"}
PICKLE_EXTS = (".pkl", ".pickle", ".pt", ".pth", ".joblib", ".bin", ".ckpt")
STRICT_EXTS = (".pkl", ".pickle")   # parse failure is suspicious (fail closed)
PROTO0_FIRST = set(b"c(}]IJKLSVXNFG)M.")
SKIP_THRESHOLD = 1024 * 1024        # larger opcode arguments are seeked over
MAX_LINE = 1024 * 1024
MAX_OPS = 5_000_000
MAX_STREAMS = 16
MAX_ZIP_MEMBERS = 256
MAX_ZIP_TOTAL = 256 * 1024 * 1024    # decompressed bytes walked per archive
MAX_PTH_READ = 1024 * 1024
PARSE_ERRORS = (ValueError, KeyError, IndexError, EOFError, struct.error,
                UnicodeDecodeError, OverflowError, zlib.error)
MARK = object()

class AnalysisLimit(Exception):
    """Raised when a pickle exceeds the static-analysis budget."""

class Skipped(bytes):
    """Stand-in for a large opcode argument that was seeked over."""
    def __new__(cls, size):
        obj = super().__new__(cls, b"")
        obj.size = size
        return obj
    def __len__(self):
        return self.size

class SkippingReader:
    """File wrapper for genops: seeks over huge arguments, bounds lines and bytes."""
    def __init__(self, fh, size, budget):
        self.fh, self.size, self.budget = fh, size, budget
    def tell(self):
        return self.fh.tell()
    def _check(self):
        if self.fh.tell() > self.budget:
            raise AnalysisLimit("decompressed byte budget exceeded")
    def read(self, n=-1):
        remaining = self.size - self.fh.tell()
        if n > SKIP_THRESHOLD and n <= remaining:
            self.fh.seek(n, io.SEEK_CUR)
            self._check()
            return Skipped(n)
        data = self.fh.read(min(n, remaining) if n >= 0 else remaining)
        self._check()
        return data
    def readline(self):
        line = self.fh.readline(MAX_LINE)
        self._check()
        return line

def apply_stack_effect(op, stack):
    """Pop/push placeholders per the opcode's documented stack effect."""
    before = op.stack_before
    if pickletools.markobject in before:
        while stack and stack.pop() is not MARK:
            pass
        del stack[max(0, len(stack) - before.index(pickletools.markobject)):]
    else:
        del stack[max(0, len(stack) - len(before)):]
    stack.extend(MARK if s is pickletools.markobject else None for s in op.stack_after)

def stream_events(reader, op_budget):
    """Yield ('global', mod, func) / ('unresolved',) events for one pickle stream."""
    stack, memo = [], {}
    for op, arg, _ in pickletools.genops(reader):
        op_budget[0] -= 1
        if op_budget[0] < 0:
            raise AnalysisLimit("opcode budget exceeded")
        name = op.name
        if name in ("GLOBAL", "INST") and isinstance(arg, str):
            mod, _, func = arg.partition(" ")
            yield ("global", mod, func)
        elif name == "STACK_GLOBAL":
            if len(stack) >= 2 and isinstance(stack[-2], str) and isinstance(stack[-1], str):
                yield ("global", stack[-2], stack[-1])
            else:
                yield ("unresolved",)
        if name in ("PUT", "BINPUT", "LONG_BINPUT"):
            memo[arg] = stack[-1] if stack else None
        elif name == "MEMOIZE":
            memo[len(memo)] = stack[-1] if stack else None
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            stack.append(memo.get(arg))
        elif name == "DUP":
            stack.append(stack[-1] if stack else None)
        elif isinstance(arg, str) and ("UNICODE" in name or "STRING" in name):
            stack.append(arg)
        else:
            apply_stack_effect(op, stack)
        if name == "STOP":
            yield ("stop",)
            return

def classify(mod, func):
    """Return "dangerous", "suspicious" or None (allowlisted) for a pickle import."""
    root, full = mod.split(".")[0], f"{mod}.{func}"
    if full.startswith(DENY_PREFIXES) or "subprocess" in full or root in DANGEROUS_ROOTS:
        return "dangerous"
    if "." in func and full not in SAFE_GLOBALS:
        # Protocol 4 resolves dotted names by attribute walk, so an allowlisted
        # module can reach any gadget (torch.nn.modules.module + "torch.cuda...Popen").
        # Only nested classes of the repo's own package are tolerated.
        if root in LOCAL_ROOTS and all(re.fullmatch(r"[A-Z][A-Za-z0-9]*", part) for part in func.split(".")):
            return None
        return "dangerous"
    if root in SHADOWED_STDLIB:
        return "dangerous"   # repo file shadows the stdlib module the pickle imports
    if root in ("builtins", "__builtin__"):
        return None if func in BUILTINS_SAFE else "dangerous"
    if root in TRUSTED_ROOTS:
        return None if TORCH_SAFE.fullmatch(full) else "dangerous"
    if full in SAFE_GLOBALS or NUMPY_SCALAR.match(full):
        return None
    if root in LOCAL_ROOTS and func not in RISKY_NAMES and not func.startswith("_"):
        return None   # the repo's own classes
    if root in STDLIB or root == "__main__":
        return "dangerous"   # stdlib holds the gadgets (uuid, pkgutil, pathlib.write_text...)
    return "suspicious"

def analyse(reader, total, strict, trusted):
    """Walk every concatenated pickle; return a finding string or None.

    strict: a parse failure of the first stream is itself a finding.
    trusted: the data is certainly a pickle. Dangerous imports always count
    (load runs REDUCE before a later parse error); suspicious imports and
    unresolved STACK_GLOBALs count immediately only in a trusted first stream,
    otherwise only when the stream reaches STOP (random-bytes FP control).
    """
    op_budget = [MAX_OPS]
    for index in range(MAX_STREAMS):
        start, pending = reader.tell(), []
        try:
            for event in stream_events(reader, op_budget):
                if event[0] == "stop":
                    break
                if event[0] == "unresolved":
                    label, issue = "unresolved", "suspicious pickle (unresolved STACK_GLOBAL)"
                else:
                    label = classify(event[1], event[2])
                    issue = label and f"{label} pickle import ({event[1]}.{event[2]})"
                if label == "dangerous" or (issue and index == 0 and trusted):
                    return issue
                if issue:
                    pending.append(issue)
            else:
                raise EOFError("stream ended without STOP")
        except AnalysisLimit as exc:
            return f"unanalysed pickle ({exc})"
        except PARSE_ERRORS:
            if index == 0 and strict:
                return "truncated or unparseable pickle"
            return None   # trailing raw data (legacy torch storages)
        if pending:
            return pending[0]
        if reader.tell() <= start or reader.tell() >= total:
            return None
    return None

def has_proto_magic(head):
    return head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05")

def check_stream(fh, size, budget, rel, strict, trusted=True):
    issue = analyse(SkippingReader(fh, size, budget), size, strict, trusted)
    if issue:
        findings.append(f"{rel}: {issue}")
    return issue

def check_zip(fpath, rel):
    """Scan pickles inside a zip (torch checkpoints) within a byte budget."""
    budget = MAX_ZIP_TOTAL
    with zipfile.ZipFile(fpath) as zf:
        members = [i for i in zf.infolist() if i.filename.endswith((".pkl", ".pickle"))]
        for info in members[:MAX_ZIP_MEMBERS]:
            if budget <= 0:
                findings.append(f"{rel}: unanalysed pickle (archive byte budget exceeded)")
                return
            name = info.filename.replace("\n", " ")[:120]
            with zf.open(info) as member:
                if check_stream(member, info.file_size, budget, f"{rel}:{name}", True):
                    return
                budget -= member.tell()

def check_pth(fpath, rel):
    with open(fpath, "r", errors="ignore") as fh:
        for line in fh.read(MAX_PTH_READ).splitlines():
            line_s = line.strip()
            if line_s.startswith(("import ", "import\t")) or "exec(" in line_s or "eval(" in line_s:
                findings.append(f"{rel}: executable startup hook ({line_s[:50]})")
                return

def repo_top_names():
    """Top-level module/package names a repo checkout puts on sys.path."""
    names = set()
    for base in (clone_dir, os.path.join(clone_dir, "src")):
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for entry in entries:
            path = os.path.join(base, entry)
            if entry.endswith(".py") and os.path.isfile(path):
                names.add(entry[:-3])
            elif os.path.isfile(os.path.join(path, "__init__.py")):
                names.add(entry)
    return names

def check_file(fpath, fname, rel):
    with open(fpath, "rb") as fh:
        head = fh.read(2)
    if fname.endswith(PICKLE_EXTS) and zipfile.is_zipfile(fpath):
        check_zip(fpath, rel)
    elif has_proto_magic(head) or (fname.endswith(PICKLE_EXTS) and not fname.endswith(".pth")
                                   and head[:1] != b"" and head[0] in PROTO0_FIRST):
        # Protocol 2+ magic, or a protocol 0/1 opcode in a pickle-named file
        magic = has_proto_magic(head)
        strict = fname.endswith(STRICT_EXTS) or (magic and fname.endswith(PICKLE_EXTS))
        trusted = magic or fname.endswith(STRICT_EXTS)
        with open(fpath, "rb") as fh:
            check_stream(fh, os.path.getsize(fpath), float("inf"), rel, strict, trusted)
    elif fname.endswith(".pth"):
        check_pth(fpath, rel)

REPO_NAMES = repo_top_names()
SHADOWED_STDLIB = REPO_NAMES & (STDLIB | DANGEROUS_ROOTS)
LOCAL_ROOTS = REPO_NAMES - STDLIB - DANGEROUS_ROOTS - TRUSTED_ROOTS - {"numpy"}
for root, dirs, files in os.walk(clone_dir):
    dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
    for fname in files:
        fpath = os.path.join(root, fname)
        rel = fpath.replace(clone_dir + "/", "")
        if os.path.islink(fpath) or not os.path.isfile(fpath):
            continue
        try:
            check_file(fpath, fname, rel)
        except Exception as exc:  # corrupt archive etc.: report, keep walking
            if fname.endswith(PICKLE_EXTS):
                findings.append(f"{rel}: unanalysed serialization file ({type(exc).__name__})")
            print(f"serialization scan error: {rel}: {exc}", file=sys.stderr)

for f in findings[:10]:
    print(f)
PYEOF
) || PTH_ERR=true
PTH_COUNT=$(echo "$PTH_HITS" | grep -c . 2>/dev/null || true)
PTH_SUSPICIOUS_ONLY=false
if [[ "$PTH_COUNT" -gt 0 ]]; then
  RESULT_PTHSERIAL="FOUND ($PTH_COUNT payloads)"
  # Only unknown third-party imports: suspicious, scored low and not high severity
  if [[ $(printf '%s\n' "$PTH_HITS" | grep -cv ': suspicious pickle' || true) -eq 0 ]]; then
    PTH_SUSPICIOUS_ONLY=true
    RESULT_PTHSERIAL="FOUND ($PTH_COUNT payloads, suspicious only)"
  fi
  DETAIL_PTHSERIAL=$(echo "$PTH_HITS" | head -3)
elif [[ "${PTH_ERR:-false}" == true ]]; then
  RESULT_PTHSERIAL="SKIPPED (error)"
  DETAIL_PTHSERIAL=""
else
  RESULT_PTHSERIAL="CLEAN"
  DETAIL_PTHSERIAL=""
fi

# ── Report ────────────────────────────────────────────────────────────────────
# Repo-derived text (filenames, JSON strings, commands) may carry terminal
# escapes or Markdown/HTML. Strip C0/C1 controls (keeping newlines) before any
# output, and escape Markdown when writing the saved report.
sanitize_text() {
  LC_ALL=C tr -d '\000-\010\013-\037\177' | LC_ALL=C sed $'s/\xc2[\x80-\x9f]//g'
}
md_escape() {
  LC_ALL=C sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
    -e 's/[]\\[()!|`*_~#{}]/\\&/g'
}
for id in GITLEAKS TRUFFLEHOG SEMGREP YARA SENS RCE DOMAINS BINSYSC ENVFILES LIFECYCLE TYPOSQUAT MCPCONFIG PTHSERIAL; do
  det_var="DETAIL_${id}"
  printf -v "$det_var" '%s' "$(printf '%s' "${!det_var}" | sanitize_text)"
done

label_GITLEAKS="Secrets in code (gitleaks)"
label_TRUFFLEHOG="Verified active secrets (trufflehog)"
label_SEMGREP="Supply chain patterns (semgrep)"
label_YARA="Malware patterns (yara)"
label_SENS="Sensitive files & AI credentials"
label_RCE="Remote code execution"
label_DOMAINS="Suspicious exfil endpoints"
label_BINSYSC="Network syscalls in binaries"
label_ENVFILES="Committed .env files"
label_LIFECYCLE="Lifecycle script abuse"
label_TYPOSQUAT="Dependency typosquatting"
label_MCPCONFIG="Insecure MCP & agent tools"
label_PTHSERIAL="Python .pth & unsafe serialization"

CHECKS="GITLEAKS TRUFFLEHOG SEMGREP YARA SENS RCE DOMAINS BINSYSC ENVFILES LIFECYCLE TYPOSQUAT MCPCONFIG PTHSERIAL"

# Risk weights per check (high=30, medium=20, low=10)
weight_GITLEAKS=20; weight_TRUFFLEHOG=30; weight_SEMGREP=10; weight_YARA=20
weight_SENS=10; weight_RCE=30; weight_DOMAINS=20; weight_BINSYSC=20
weight_ENVFILES=20; weight_LIFECYCLE=30; weight_TYPOSQUAT=20
weight_MCPCONFIG=30; weight_PTHSERIAL=30
# Decode-then-exec proximity alone is a weaker signal than a single expression
weight_YARA_LOW=10
weight_PTHSERIAL_LOW=10

RISK_SCORE=0
MAX_SCORE=0
for id in $CHECKS; do
  w_var="weight_${id}"
  MAX_SCORE=$((MAX_SCORE + ${!w_var}))
done

echo ""
WIDTH=70
BORDER=$(printf '─%.0s' $(seq 1 $WIDTH))
echo -e "${BOLD}${CYAN}┌${BORDER}┐${RESET}"
printf "${BOLD}${CYAN}│${RESET}  %-36s  %-30s${BOLD}${CYAN}│${RESET}\n" "CHECK" "RESULT"
echo -e "${BOLD}${CYAN}├${BORDER}┤${RESET}"

FOUND_ANY=false
HIGH_SEVERITY=false
for id in $CHECKS; do
  res_var="RESULT_${id}"; det_var="DETAIL_${id}"; lbl_var="label_${id}"; w_var="weight_${id}"
  res="${!res_var}"; det="${!det_var}"; lbl="${!lbl_var}"; w="${!w_var}"
  [[ "$id" == "YARA" && "$YARA_LOW_CONFIDENCE" == true ]] && w=$weight_YARA_LOW
  low_pth=false
  [[ "$id" == "PTHSERIAL" && "$PTH_SUSPICIOUS_ONLY" == true ]] && { w=$weight_PTHSERIAL_LOW; low_pth=true; }

  # Accumulate risk score
  # WARN (incomplete analysis) and SKIPPED are shown in yellow but not scored
  if [[ "$res" != "CLEAN" && "$res" != SKIPPED* && "$res" != WARN* ]]; then
    RISK_SCORE=$((RISK_SCORE + w))
    FOUND_ANY=true
    # High severity: RCE, lifecycle abuse, verified secrets, MCP risk, .pth execution
    [[ "$id" == "RCE" || "$id" == "LIFECYCLE" || "$id" == "TRUFFLEHOG" || "$id" == "MCPCONFIG" || ( "$id" == "PTHSERIAL" && "$low_pth" == false ) ]] && HIGH_SEVERITY=true
  fi

  # Color for result
  if [[ "$res" == "CLEAN" ]]; then
    res_colored="${GREEN}${res}${RESET}"
  elif [[ "$res" == SKIPPED* || "$res" == WARN* ]]; then
    res_colored="${YELLOW}${res}${RESET}"
  else
    res_colored="${RED}${res}${RESET}"
  fi

  printf "${BOLD}${CYAN}│${RESET}  %-36s  %b" "$lbl" "$res_colored"
  res_plain=$(echo "$res" | sed 's/\x1b\[[0-9;]*m//g')
  pad=$((WIDTH - 36 - 2 - ${#res_plain} - 2))
  [[ $pad -lt 0 ]] && pad=0
  printf '%*s' "$pad" ""
  echo -e "${BOLD}${CYAN}│${RESET}"

  if [[ -n "$det" ]]; then
    while IFS= read -r line; do
      line="${line:0:$((WIDTH - 6))}"
      printf "${BOLD}${CYAN}│${RESET}    ${YELLOW}↳${RESET} %-$((WIDTH - 6))s${BOLD}${CYAN}│${RESET}\n" "$line"
    done <<< "$det"
  fi
done

# Risk score row
echo -e "${BOLD}${CYAN}├${BORDER}┤${RESET}"
RISK_PCT=$(( (RISK_SCORE * 100) / MAX_SCORE ))
if [[ $RISK_PCT -ge 60 ]]; then
  RISK_COLOR="$RED"
elif [[ $RISK_PCT -ge 30 ]]; then
  RISK_COLOR="$YELLOW"
else
  RISK_COLOR="$GREEN"
fi
RISK_LABEL="Risk score"
RISK_VAL="${RISK_COLOR}${RISK_PCT}/100${RESET}"
printf "${BOLD}${CYAN}│${RESET}  %-36s  %b" "$RISK_LABEL" "$RISK_VAL"
risk_plain="${RISK_PCT}/100"
pad=$((WIDTH - 36 - 2 - ${#risk_plain} - 2))
[[ $pad -lt 0 ]] && pad=0
printf '%*s' "$pad" ""
echo -e "${BOLD}${CYAN}│${RESET}"

echo -e "${BOLD}${CYAN}└${BORDER}┘${RESET}"
echo -e "  Scanned: ${BOLD}$REPO_URL${RESET}"
echo ""

# ── Save report? ──────────────────────────────────────────────────────────────
SAVE_REPORT=false
if [[ "$AUTO_SAVE" == true ]]; then
  SAVE_REPORT=true
elif [[ "$NO_INTERACTIVE" != true ]]; then
  read -rp "  Save report as Markdown? [y/N]: " SAVE
  [[ "$SAVE" =~ ^[Yy]$ ]] && SAVE_REPORT=true
fi

if [[ "$SAVE_REPORT" == true ]]; then
  REPORT_FILE="$OUT_DIR/${REPO_NAME}-security-report.md"
  {
    echo "# Security Scan Report: $(printf '%s' "$REPO_NAME" | sanitize_text | md_escape)"
    echo ""
    echo "> Scanned: $(printf '%s' "$REPO_URL" | sanitize_text | md_escape)  "
    echo "> Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "> Risk score: ${RISK_PCT}/100"
    echo ""
    echo "## Results"
    echo ""
    echo "| Check | Result | Files |"
    echo "|-------|--------|-------|"
    for id in $CHECKS; do
      res_var="RESULT_${id}"; det_var="DETAIL_${id}"; lbl_var="label_${id}"
      res="${!res_var}"; det="${!det_var}"; lbl="${!lbl_var}"
      raw_detail=""
      if [[ -n "$det" ]]; then
        raw_detail=$(printf '%s\n' "$det" | md_escape | paste -sd ',' - | sed 's/,/, /g')
      fi
      echo "| $lbl | $res | $raw_detail |"
    done
    echo ""
    if [[ "$FOUND_ANY" == true ]]; then
      echo "## Findings Detail"
      echo ""
      for id in $CHECKS; do
        det_var="DETAIL_${id}"; lbl_var="label_${id}"
        det="${!det_var}"; lbl="${!lbl_var}"
        if [[ -n "$det" ]]; then
          # Indented code block of escaped text: it cannot close the block, and
          # no viewer turns it into an image, link or HTML
          echo "### $lbl"
          echo ""
          printf '%s\n' "$det" | md_escape | sed 's/^/    /'
          echo ""
        fi
      done
    fi
  } > "$REPORT_FILE"
  echo -e "  ${GREEN}Report saved → $REPORT_FILE${RESET}"
fi

# ── No-interactive exit ───────────────────────────────────────────────────────
if [[ "$NO_INTERACTIVE" == true ]]; then
  if [[ "$HIGH_SEVERITY" == true ]]; then
    echo -e "  ${RED}High-severity findings detected. Exiting with code 1.${RESET}"
    exit 1
  fi
  exit 0
fi

echo ""
