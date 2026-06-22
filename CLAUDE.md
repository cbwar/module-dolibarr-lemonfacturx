# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**LemonFacturX** is a Dolibarr module (module ID 210000) that automatically converts customer invoices to **Factur-X EN16931** format — PDF/A-3 files with an embedded CrossIndustryInvoice XML — conforming to French BR-FR rules (XP Z12-012 V1.2.0). It is installed under `custom/lemonfacturx/` in a Dolibarr instance.

## Commands

### Lint (all PHP files, excluding vendor)
```bash
find . -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l > /dev/null && echo "Lint OK"
```

### Run unit tests (no Dolibarr needed)
```bash
php tests/unit-tests.php
```
Exit 0 = all tests pass, exit 1 = failure. Covers 18 scenarios / 100+ assertions with XSD + business rule (BR-*) validation per generated XML.

### Run integration tests (requires a live Dolibarr with demo fixtures loaded)
```bash
php tests/run-tests.php
```

### Export Factur-X XML batch (CLI, Dolibarr environment required)
```bash
php scripts/export_facturx_batch.php /path/to/export [year]
```

### Build release ZIP (CI does this on tag push)
The release ZIP is built by `.github/workflows/release-zip.yml` on `v*` tags. The ZIP root must be `lemonfacturx/` — not the repo root name — for Dolibarr to install it correctly.

### Vendor management
`vendor/` is committed. Dependencies are managed via `composer.json` (locally), but Composer is **not required** on the deployment server. To rebuild vendor:
```bash
composer install --no-dev
```
**Important**: `vendor/setasign/fpdf/fpdf.php` has a custom patch (`/F 4` flag on annotations for PDF/A-3 compliance). Re-apply it after any `fpdf` upgrade.

## Architecture

```
core/modules/modLemonFacturX.class.php   # Module descriptor (ID 210000), hooks registration
core/lib/lemonfacturx.lib.php            # XML EN16931 generator (main logic)
core/lib/lemonfacturx_rules.php          # BR-* business rule validator (PHP subset of Schematron)
class/actions_lemonfacturx.class.php     # Hooks: afterPDFCreation + invoicecard actions
class/api_lemonfacturx.class.php         # REST API: /xml and /status endpoints
admin/setup.php                          # Settings page + diagnostic
chorus_tab.php                           # Chorus Pro tab on invoice card (since 3.4.0)
scripts/export_facturx_batch.php         # Batch XML extractor
tests/unit-tests.php                     # Standalone tests (no Dolibarr)
tests/stubs.php                          # Dolibarr stubs for standalone tests
```

### Data flow

1. Hook `afterPDFCreation` fires after Dolibarr generates a customer invoice PDF.
2. `lemonfacturx_check_supported()` rejects multidevise and local-tax invoices (clean fail, classic PDF preserved).
3. `lemonfacturx_generate_xml()` builds the CrossIndustryInvoice XML from the Dolibarr `Facture` object.
4. Internal validation: well-formed → XSD EN16931 → BR-* rules (`lemonfacturx_rules.php`).
5. `ActionsLemonFacturX::injectXmlIntoPdf()` calls `\Atgp\FacturX\Writer::generate()` in-process to embed the XML into the PDF atomically (temp file + `rename()`).
6. Optional post-validation via veraPDF (`LEMONFACTURX_VERAPDF_PATH`).

For **Chorus Pro** invoices (B2G, detected by flag or SIRET), a second PDF `{ref}-CHORUS.pdf` is generated in parallel with a SIRET-14 identifier instead of SIREN-9.

### Key design decisions

- **Two separate legal identifiers**: SIRET (14 digits) goes to `ram:ID` schemeID 0009 (BT-29/BT-46); SIREN (9 digits) goes to `SpecifiedLegalOrganization/ram:ID` schemeID 0002 (BT-30/BT-47). This is required by BR-FR-10 and Plateformes Agréées routing.
- **Credit notes**: Dolibarr stores negative totals; EN16931 requires positive amounts on type 381. All amounts are inverted, `DuePayableAmount` is exact (no clamping to zero, which would violate BR-CO-16).
- **Negative-price lines → BG-21 allowances**: a negative-price line would violate BR-27, so they're converted to document-level allowances.
- **VAT rounding reconciliation**: VAT breakdown is computed per (category, rate) then reconciled against invoice totals; the rounding delta is absorbed by the primary category. All BG-22 totals are recomputed bottom-up.
- **In-process injection**: `\Atgp\FacturX\Writer` is called directly inside the web process. This is safe because `class FPDF` in `setasign/fpdf` is patched to `class SetasignFPDF` (via `patches/fpdf.patch` + `patches/fpdi.patch`), eliminating the class conflict with Dolibarr's own FPDF. The patches are applied automatically by `composer install` (`post-install-cmd` in `composer.json`).
- **Best-effort vs strict**: in best-effort (default), XML/injection failures show a warning and the classic PDF is kept. In strict mode (`LEMONFACTURX_STRICT_MODE=1`), BR-* violations and injection errors are blocking. Note: the classic PDF already written to disk is never deleted either way.

### Security constraints

- `scripts/`, `tests/`, `demo/` are guarded by `PHP_SAPI === 'cli'` **and** `.htaccess Require all denied`.
- `exec()` is verified before use; the PHP CLI path is validated by regex + `is_executable()`.
- CSRF protection on all admin POST and invoice card actions via `currentToken()`.
- The only outbound HTTP call is a GitHub version check (24h cache in DB, failures cached too).

## Testing notes

`tests/unit-tests.php` runs standalone without Dolibarr by loading `tests/stubs.php` which provides fake `Facture`, `Societe`, `Conf`, `Translate` objects. Each test scenario calls `lemonfacturx_generate_xml()` and then validates the output against the XSD at `vendor/atgp/factur-x/xsd/factur-x/en16931/Factur-X_1.08_EN16931.xsd` plus the internal BR-* rules.

The CI (`.github/workflows/ci.yml`) runs lint + unit tests on every push/PR. The release workflow (`.github/workflows/release-zip.yml`) also runs them before packaging.

## Known limitations (do not try to "fix" these without reading docs/LIMITATIONS.md)

- **Multidevise**: rejected at generation time (clean fail) — Dolibarr doesn't store per-line multicurrency VAT breakdown.
- **Local taxes (localtax1/2)**: rejected — not representable in EN16931.
- **Official Schematron**: not executable in PHP (requires XSLT 2.0). The internal validator covers the most-checked BR-* rules only.
- **Type CODE 389 (self-billing)**, **O/Z/L/M VAT categories**, **SKONTO structured discount**: not implemented.
- **Chorus Pro PDF** corrects the *format* only — the emitter and public structure must actually be enrolled on Chorus Pro for deposits to succeed.
