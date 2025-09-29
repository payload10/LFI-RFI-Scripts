#!/bin/bash

# Download payload list if not already present
if [ ! -f "lfi_payloads.txt" ]; then
    curl -s -L "https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt" -o lfi_payloads.txt
fi

# Clean file (remove comments and duplicates)
grep -v "^#" lfi_payloads.txt | sort -u > lfi_payloads.clean.txt

# Split Linux payloads (look for /etc, /proc, /var etc.)
grep -F "/etc/" lfi_payloads.clean.txt > linux_payloads.txt
grep -F "/proc/" lfi_payloads.clean.txt >> linux_payloads.txt
grep -F "/var/" lfi_payloads.clean.txt >> linux_payloads.txt

# Split Windows payloads (look for C:\, boot.ini, win.ini etc.)
grep -i -F "C:/" lfi_payloads.clean.txt > windows_payloads.txt
grep -i -F "boot.ini" lfi_payloads.clean.txt >> windows_payloads.txt
grep -i -F "win.ini" lfi_payloads.clean.txt >> windows_payloads.txt
grep -i -F "WINDOWS" lfi_payloads.clean.txt >> windows_payloads.txt

# Print stats
echo -e "\033[36mTotal payloads:\033[0m $(wc -l < lfi_payloads.clean.txt)"
echo -e "\033[36mLinux payloads:\033[0m $(wc -l < linux_payloads.txt)"
echo -e "\033[36mWindows payloads:\033[0m $(wc -l < windows_payloads.txt)"
