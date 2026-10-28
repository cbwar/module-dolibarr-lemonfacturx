#!/usr/bin/env bash
# Build script — produit dist/module_lemonfacturx-<VERSION>.zip
# Usage : ./build.sh [VERSION]
#   VERSION  : nom du tag (ex: v3.5.1). Défaut : "dev"
#
# Prérequis : php, composer, zip, rsync
#
# Le nom suit le format Dolistore « module_<nom>-x.y.z.zip » (version SANS le
# « v » du tag) et le dossier racine du ZIP est lemonfacturx/ (requis par Dolibarr).

set -euo pipefail

VERSION="${1:-dev}"
VERSION="${VERSION#v}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${ROOT}/dist"
OUT="${DIST_DIR}/module_lemonfacturx-${VERSION}.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cd "$ROOT"

echo "Install dependencies"
composer install --no-dev --quiet

echo "Regenerate autoloader (after patches)"
composer dump-autoload --optimize --no-dev --quiet

if ! grep -q 'class SetasignFPDF' vendor/setasign/fpdf/fpdf.php; then
    echo "ERROR: vendor/setasign/fpdf is not patched (class SetasignFPDF missing)" >&2
    exit 1
fi

echo "Creating archive"
mkdir -p "$DIST_DIR"
rm -f "$OUT"
mkdir -p "$STAGE/lemonfacturx"
rsync -a --exclude='/dist' --exclude='/.git' ./ "$STAGE/lemonfacturx/"
(cd "$STAGE" && zip -r "$OUT" lemonfacturx \
    --exclude 'lemonfacturx/*.git*' \
    --exclude 'lemonfacturx/.github/*' \
    --exclude 'lemonfacturx/.gitignore' \
    --exclude 'lemonfacturx/.gitattributes' \
    --exclude 'lemonfacturx/*.md' \
    --exclude 'lemonfacturx/build.sh' \
    --exclude 'lemonfacturx/tests/*' \
    --exclude 'lemonfacturx/demo/*' \
    --exclude 'lemonfacturx/composer.json' \
    --exclude 'lemonfacturx/composer.lock' \
    --exclude 'lemonfacturx/dist/*' \
    --exclude 'lemonfacturx/patches/*' \
    --exclude 'lemonfacturx/vendor/*/*/tests/*' \
    --exclude 'lemonfacturx/vendor/*/*/test/*' \
    --exclude 'lemonfacturx/vendor/*/*/doc/*' \
    --exclude 'lemonfacturx/vendor/*/*/docs/*' \
    --exclude 'lemonfacturx/vendor/*/*/tutorial/*' \
    --exclude 'lemonfacturx/vendor/*/*/makefont/*' \
    --exclude 'lemonfacturx/vendor/*/*/img/*' \
    --exclude 'lemonfacturx/vendor/*/*/.github/*')

echo "Created: $OUT"
