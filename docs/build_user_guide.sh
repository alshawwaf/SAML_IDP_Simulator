#!/usr/bin/env bash
# Regenerate docs/USER_GUIDE.docx from docs/USER_GUIDE.md.
#
# Run from anywhere — the script resolves paths relative to itself.
# Embeds any images present in docs/guide/images/ that the markdown references.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "pandoc not installed. macOS: brew install pandoc"
  echo "                     Debian/Ubuntu: sudo apt-get install pandoc"
  exit 1
fi

echo "Regenerating USER_GUIDE.docx from USER_GUIDE.md ..."

pandoc USER_GUIDE.md \
  -o USER_GUIDE.docx \
  --from markdown \
  --to docx \
  --syntax-highlighting=tango \
  --toc \
  --toc-depth=2 \
  --metadata title="SAML + SCIM IDP Simulator — User Guide" \
  --metadata author="Khalid Al-Shawwaf · Check Point"

bytes=$(stat -f%z USER_GUIDE.docx 2>/dev/null || stat -c%s USER_GUIDE.docx)
echo "Wrote $(pwd)/USER_GUIDE.docx ($bytes bytes)."

missing=0
while IFS= read -r line; do
  if [[ -n "$line" && ! -f "$line" ]]; then
    echo "  ⚠️  Markdown references missing image: $line"
    missing=$((missing + 1))
  fi
done < <(grep -oE '!\[[^]]*\]\(guide/images/[^)]+\)' USER_GUIDE.md | sed -E 's/^!\[[^]]*\]\((.+)\)$/\1/')

if [[ $missing -gt 0 ]]; then
  echo
  echo "$missing image(s) missing under guide/images/. The docx will render placeholders for those — see guide/images/README.md."
fi
