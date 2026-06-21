#!/usr/bin/env bash
# Build script — produit dist/lemonfacturx-<VERSION>.zip
# Usage : ./build.sh [VERSION]
#   VERSION  : nom du tag (ex: v3.5.1). Défaut : "dev"
#
# Prérequis : php, composer, zip

VERSION="${1:-dev}"
DIST_DIR="$(dirname "$0")/dist"
OUT="${DIST_DIR}/lemonfacturx-${VERSION}.zip"

echo "==> Lint PHP (hors vendor/)"
find . -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l > /dev/null
echo "    OK"

echo "==> composer install --no-dev"
composer install --no-dev --optimize-autoloader --quiet

echo "==> Assemblage de l'archive"
mkdir -p "$DIST_DIR"
test -f "$OUT" && rm -v "$OUT"
zip -r "$OUT" . \
    --exclude '*.git*' \
    --exclude '.github/*' \
    --exclude '.gitignore' \
    --exclude '.gitattributes' \
    --exclude '*.md' \
    --exclude 'build.sh' \
    --exclude 'tests/*' \
    --exclude 'demo/*' \
    --exclude 'composer.json' \
    --exclude 'composer.lock' \
    --exclude 'dist/*' \
    --exclude 'vendor/*/*/tests/*' \
    --exclude 'vendor/*/*/test/*' \
    --exclude 'vendor/*/*/doc/*' \
    --exclude 'vendor/*/*/docs/*' \
    --exclude 'vendor/*/*/tutorial/*' \
    --exclude 'vendor/*/*/makefont/*' \
    --exclude 'vendor/*/*/img/*' \
    --exclude 'vendor/*/*/.github/*'

echo "==> Created archive : $OUT"
