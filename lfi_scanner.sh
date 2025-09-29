#!/usr/bin/env bash
printf "\n"
# lfi_scanner.sh — LFI-only sequential scanner (no proxy)
set -euo pipefail

# Colors
COLOR_RESET=$'\033[0m'
COLOR_DARK_RED=$'\033[0;31m'
COLOR_DARK_GREEN=$'\033[0;32m'
COLOR_LIGHT_CYAN=$'\033[1;36m'
COLOR_MUTED_BLUE=$'\033[0;36m'   # muted blue for the (no obvious LFI) suffix
COLOR_YELLOW=$'\033[0;33m'
COLOR_WHITE=$'\033[0;37m'
COLOR_DARK_RED=$'\033[0;31m'
COLOR_RESET=$'\033[0m'

# Defaults
TIMEOUT=12
GAP=0.4
USER_AGENT="lfi-only-scanner/1.0"
TMPDIR="$(mktemp -d -t lfi.XXXX)"
SAVE_DIR="./matched_bodies_lfi"
SAVE_BODIES=false
BASELINE_TOKEN="BASELINE_TOKEN_DO_NOT_EXIST_9f3b"

# Force no proxy
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy no_proxy NO_PROXY

# LFI detection keywords
LFI_KEYWORDS=(
  'root:.*:0:0:'
  'root:x:'
  '/bin/ash'
  'UID\s*=\s*0'
  '<\?php'
  'No such file or directory'
  'Permission denied'
  'Warning:\s+include'
  'Warning:\s+require'
  'Fatal error'
  'file_get_contents'
)

# helpers
info(){ printf "%b\n" "${COLOR_LIGHT_CYAN}$*${COLOR_RESET}"; }
note(){ printf "%b\n" "${COLOR_YELLOW}$*${COLOR_RESET}"; }
ok(){ printf "%b\n" "${COLOR_DARK_GREEN}$*${COLOR_RESET}"; }
err(){ printf "%b\n" "${COLOR_DARK_RED}$*${COLOR_RESET}"; }
plain(){ printf "%b\n" "${COLOR_WHITE}$*${COLOR_RESET}"; }

csv_safe(){ local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

# prompt
prompt(){ local var="$1"; local txt="$2"; printf "%b" "${COLOR_LIGHT_CYAN}${txt}${COLOR_RESET}"; read -r "$var"; }

# fetch (ignore tls certs)
fetch_to_file(){
  local url="$1"; local out="$2"
  curl -sS -k --max-time "$TIMEOUT" -A "$USER_AGENT" -L "$url" -o "$out"
}

# check lfi keywords -> prints matching line if any and returns 0
check_lfi_keywords(){
  local f="$1"
  for kw in "${LFI_KEYWORDS[@]}"; do
    if grep -Eiq -- "$kw" "$f" 2>/dev/null; then
      grep -Eim1 -- "$kw" "$f" 2>/dev/null | head -c 200 || true
      return 0
    fi
  done
  return 1
}

sanitize_fname(){ echo "$1" | sed 's#[:/?&=]#_#g' | tr -s '_' | cut -c1-200; }

# Interactive inputs
printf "%b\n\n" "${COLOR_DARK_RED}WARNING: Identify your target's backend server (Windows or Linux). Based on that, provide the appropriate LFI payload list.${COLOR_RESET}"
prompt LFI_PAYLOADS_FILE "Enter input file for payloads (LFI payload list you will provide): "
if [[ ! -f "$LFI_PAYLOADS_FILE" ]]; then err "File not found: $LFI_PAYLOADS_FILE"; exit 1; fi

prompt LFI_URLS_FILE "Input file for LFI URLs with parameter values as FUZZ: "
if [[ ! -f "$LFI_URLS_FILE" ]]; then err "File not found: $LFI_URLS_FILE"; exit 1; fi

printf "\n"
prompt USER_GAP "Enter gap/delay between requests in seconds (e.g. 0.4): "
if [[ -z "$USER_GAP" ]]; then USER_GAP="$GAP"; fi
GAP="$USER_GAP"

prompt SAVE_ANS "Save matched response bodies? (y/N): "
if [[ "${SAVE_ANS}" =~ ^([yY])$ ]]; then SAVE_BODIES=true; mkdir -p "$SAVE_DIR"; fi

# Load arrays (cleaned)
mapfile -t LFI_PAYLOADS < <(sed -E '/^\s*($|#)/d' "$LFI_PAYLOADS_FILE")
mapfile -t LFI_URLS     < <(sed -E '/^\s*($|#)/d' "$LFI_URLS_FILE")

if [[ ${#LFI_PAYLOADS[@]} -eq 0 || ${#LFI_URLS[@]} -eq 0 ]]; then err "Empty payloads or urls file."; exit 1; fi

total=0; hits=0
info "=== Starting LFI scan (sequential) ==="

for url_template in "${LFI_URLS[@]}"; do
  if [[ "$url_template" != *FUZZ* ]]; then plain "Skipping (no FUZZ token): $url_template"; continue; fi
  for payload in "${LFI_PAYLOADS[@]}"; do
    total=$((total+1))
    target="${url_template//FUZZ/$payload}"
    bodyfile="${TMPDIR}/lfi_${total}_$((RANDOM)).body"

    if ! fetch_to_file "$target" "$bodyfile"; then
      plain "[ERR] $target (request failed or timed out)"
      sleep "$GAP"
      continue
    fi

    body_len=$(wc -c < "$bodyfile" 2>/dev/null || echo 0)

    if snippet=$(check_lfi_keywords "$bodyfile"); then
      hits=$((hits+1))
      printf "%b" "${COLOR_DARK_GREEN}${target}${COLOR_RESET}"
      printf " "
      printf "%b\n" "${COLOR_DARK_RED}- Potentially Vulnerable LFI${COLOR_RESET}"
      note "Snippet: $(echo "$snippet" | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if $SAVE_BODIES; then fname="$(sanitize_fname "$target")__LFI__${hits}.html"; cp -f "$bodyfile" "${SAVE_DIR}/${fname}" 2>/dev/null || true; fi
    else
      # no obvious LFI -> print URL normal and colored suffix in muted blue
      printf "[%s bytes] %s %b(no obvious LFI)%b\n" "$body_len" "$target" "$COLOR_MUTED_BLUE" "$COLOR_RESET"
    fi

    rm -f "$bodyfile"
    sleep "$GAP"
  done
done

info "=== LFI scan complete. Hits found: ${hits} (total requests: ${total}) ==="
if $SAVE_BODIES; then info "Saved matched bodies to ${SAVE_DIR}"; fi
rm -rf "$TMPDIR"
exit 0
