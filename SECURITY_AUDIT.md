# Rapport de sécurité — Module LemonFacturX (Dolibarr)

**Cible auditée :** `hello-lemon/module-dolibarr-lemonfacturx`
**Version analysée :** 3.5.0 (dernière release), branch `test` au 22 juin 2026
**Contexte :** module complémentaire Dolibarr pour la génération de factures Factur-X EN16931, déployé en environnement self-hosted (Dolibarr 21)
**Méthode :** revue de code statique intégrale — tous les fichiers PHP hors `vendor/` et `tests/` ont été couverts lors de cette mise à jour. Recherche de CVE sur les dépendances (composer.lock). Analyse de la documentation publique (README, SECURITY.md).
**Limites :** aucun test dynamique (fuzzing, pentest) effectué. Absence d'audit de `atgp/factur-x` v3.3.0 au-delà de ses CVE publiées.

---

## Résumé exécutif

Le module présente un **niveau de maturité sécurité supérieur à la moyenne** des modules communautaires Dolibarr : échappement systématique des arguments shell, validation des chemins de binaires, isolation des scripts CLI, écriture atomique des fichiers. Aucune injection de commande ou de path traversal exploitable sans accès préalable à la base de données n'a été identifiée.

**Un nouveau constat de sévérité moyenne a été identifié lors de cette mise à jour** (2.10) : logique CSRF incorrecte dans `chorus_tab.php` (`newToken()` au lieu de `currentToken()`), contrairement au pattern correct utilisé dans tous les autres fichiers du module.

| Sévérité | Nombre de constats |
|---|---|
| 🔴 Élevée | 0 |
| 🟠 Moyenne | 1 |
| 🟡 Faible | 2 |
| 🔵 Informative | 4 |
| ✅ Résolu depuis audit initial | 7 |

---

## 1. Constats — Dépendances vendored

### ✅ 1.1 `setasign/fpdi` — DoS par épuisement mémoire (CWE-770) — **RÉSOLU**

**CVE-2026-45802** (GHSA-2mgw-7q6p-8grg), sévérité **MODERATE** (CVSS 4.0 : 6.0).

> Prior to version 2.6.7, an attacker can upload a small, malicious PDF file that will cause the server-side script to crash due to memory exhaustion or a script time-out. Repeated attacks can lead to sustained service unavailability.

L'audit initial pointait la version 2.6.6. Le `composer.lock` (ajouté le 21 juin 2026) fixe désormais `setasign/fpdi` à **v2.6.8** — la CVE est corrigée depuis 2.6.7. **Constat clos.**

*Note connexe (non bloquante) :* **CVE-2025-54869** (CWE-770, corrigée en 2.6.3) est également couverte par 2.6.8.

### ✅ 1.2 `setasign/fpdf` — upload de fichier arbitraire via `AddFont()` — **RÉSOLU**

**CVE-2025-65875**, sévérité **HIGH** (CVSS 3.1 : 8.8), affectait `v1.86 et antérieur`.

L'audit initial pointait la version 1.8.6. Le `composer.lock` fixe désormais `setasign/fpdf` à **v1.9.0**, qui sort du périmètre de la CVE (celle-ci couvre ≤ 1.86). **Constat clos.**

*Note :* la vérification de l'usage réel de `AddFont()` dans `atgp/factur-x` (recommandée dans l'audit initial) n'est plus bloquante — la version 1.9.0 embarquée n'est pas affectée.

### ✅ 1.3 `composer.lock` et audit automatisé des dépendances — **PARTIELLEMENT RÉSOLU**

Le `composer.json` et le `composer.lock` ont été ajoutés le 21 juin 2026. Dependabot, `composer audit` et les outils équivalents peuvent désormais scanner les dépendances de façon automatisée. La veille CVE n'est plus entièrement manuelle.

**État actuel (WIP) :** le répertoire `vendor/` a été retiré du dépôt git dans le même batch de commits. Le workflow de release (`release-zip.yml`) **ne lance pas encore `composer install`** — un tag poussé maintenant produirait une archive ZIP sans `vendor/`, rendant le module non fonctionnel à l'installation. Voir le constat 1.4 ci-dessous.

**Recommandation :** vérifier que `release-zip.yml` est mis à jour avant le prochain tag.

### ✅ 1.4 Workflow de release aligné sur le nouveau modèle Composer — **RÉSOLU**

`composer install --no-dev` a été intégré au workflow `.github/workflows/release-zip.yml`. L'archive ZIP inclut désormais `vendor/` — le module est installable normalement depuis une release taguée. **Constat clos.**

---

## 2. Constats — Code propre au module

### 2.1 ✅ Construction de la commande `exec()` — **RÉSOLU** (exec supprimé)

L'injection XML dans le PDF se faisait via un subprocess `exec()` appelant `scripts/inject_facturx.php`, avec tous les arguments protégés par `escapeshellarg()`. Aucune injection de commande shell n'avait été identifiée.

**Mise à jour 22/06/2026 :** l'appel `exec()` a été supprimé de `afterPDFCreation()` et `generateChorusPdf()`. L'injection utilise désormais `\Atgp\FacturX\Writer::generate()` directement dans le process web, rendu possible par le renommage de `class FPDF` → `class SetasignFPDF` dans `vendor/setasign/fpdf/fpdf.php` (patch `patches/fpdf.patch`) qui élimine le conflit de classe avec le FPDF embarqué dans Dolibarr. `resolvePhpBinary()` et `$xmlTmpFile` ont été supprimés. **Constat clos — voir constat 2.19 pour le nouveau modèle d'isolation.**

### 2.2 ✅ Origine des chemins de fichiers

- `$file` provient de `$parameters['file']`, fourni par le hook Dolibarr core `afterPDFCreation` — pas d'entrée utilisateur directe.
- Le fichier XML temporaire (`tempnam()` dans `DOL_DATA_ROOT/facturx/temp/`) n'est plus créé dans le flux principal : le XML est passé en chaîne directement à `Writer::generate()`.

**Aucun path traversal identifié** sur ces paramètres dans le code revu.

### 2.3 ✅ Validation de `LEMONFACTURX_PHP_CLI_PATH` — **RÉSOLU** (paramètre supprimé)

L'audit pointait la surface de confiance élargie autour de `LEMONFACTURX_PHP_CLI_PATH` : tout admin Dolibarr pouvait modifier ce chemin, qui était ensuite utilisé dans `exec()`.

**Mise à jour 22/06/2026 :** `resolvePhpBinary()` a été supprimé et `LEMONFACTURX_PHP_CLI_PATH` n'est plus utilisé par le code d'injection. La surface d'attaque associée est éliminée. **Constat clos.**

*Note :* si le paramètre `LEMONFACTURX_PHP_CLI_PATH` subsiste dans `admin/setup.php` comme champ configurable, il doit être retiré de l'interface pour éviter toute confusion.

### 2.4 ✅ Absence de timeout shell sur les subprocessus d'injection — **RÉSOLU** (subprocessus supprimés)

L'audit signalait l'absence de timeout sur les subprocessus d'injection principale et Chorus, contrairement au traitement déjà en place pour veraPDF.

**Mise à jour 22/06/2026 :** les deux subprocessus d'injection (`inject_facturx.php`) ont été supprimés. L'injection se fait maintenant en mémoire via `Writer::generate()`, soumis au `max_execution_time` normal du process web. Seul `runVeraPdf()` conserve un `exec()`, avec le timeout de 60 s déjà en place. **Constat clos — voir constat 2.19 pour les implications du nouveau modèle.**

### 2.5 🟡 Absence de contrôle de type/taille avant chargement du PDF en mémoire

L'audit initial ciblait `inject_facturx.php`. Ce script n'est plus appelé par le flux principal (injection désormais inline), mais le constat reste actif sous une forme révisée.

**Mise à jour 22/06/2026 :** `injectXmlIntoPdf()` charge le PDF avec `file_get_contents($pdfPath)` sans vérification de taille ni de signature `%PDF-` :

```php
$pdfContent = file_get_contents($pdfPath);  // pas de limite de taille
```

Avec l'ancien modèle subprocess, un PDF pathologique ne pouvait au pire crasher que le process CLI isolé. Avec l'injection in-process, il est traité directement dans le process web — un PDF de plusieurs centaines de Mo pourrait provoquer une exhaustion mémoire OOM visible par les autres requêtes. L'origine de `$pdfPath` reste contrôlée (cf. 2.2), mais la defense-in-depth est absente.

**Recommandation :** ajouter dans `injectXmlIntoPdf()` une vérification de taille maximale et de signature avant le chargement :

```php
if (filesize($pdfPath) > 50 * 1024 * 1024) {  // 50 Mo — ajuster selon usage
    return lemonfacturx_trans('LemonFacturXErrInjectFailed').' : PDF too large';
}
$pdfContent = file_get_contents($pdfPath);
if ($pdfContent === false || substr($pdfContent, 0, 4) !== '%PDF') {
    return lemonfacturx_trans('LemonFacturXErrInjectFailed').' : not a PDF';
}
```

### 2.6 🔵 Garde CLI et protection `.htaccess`

```php
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die('Access denied');
}
```

Bonne pratique de défense en profondeur, cohérente avec le `.htaccess Require all denied` annoncé sur les répertoires `scripts/`, `tests/`, `demo/` (non vérifié directement dans les fichiers fournis — à confirmer sur l'installation réelle).

**Recommandation :** vérifier sur votre instance que ces fichiers `.htaccess` sont bien présents et actifs (dépend de `AllowOverride` côté Apache, ou de l'absence d'équivalent si vous utilisez Nginx — dans ce dernier cas, le `.htaccess` Apache est **sans effet** et une règle Nginx équivalente doit être ajoutée manuellement).

### 2.7 🔵 Gestion des erreurs et nettoyage

**Mise à jour 22/06/2026 :** le fichier XML temporaire et le `try/finally` de nettoyage associé ont été supprimés du flux principal — le XML est désormais passé en chaîne à `Writer::generate()`, sans écriture sur disque. L'écriture atomique (`tempnam` + `rename`) est conservée dans `injectXmlIntoPdf()` pour le PDF résultant : le nouveau fichier est écrit dans `{pdf}.facturx.tmp` puis renommé sur l'original. Bonne robustesse maintenue face aux échecs partiels.

### 2.8 ✅ `admin/setup.php` — contrôles d'accès et sanitisation des entrées

- Garde d'accès `if (!$user->admin) { accessforbidden(); }` en tête de fichier.
- CSRF vérifié sur toutes les actions POST (`GETPOST('token', 'alpha') !== currentToken()`), y compris l'action `setforcefont`.
- Entrées filtrées avec les helpers Dolibarr appropriés : `GETPOSTINT`, `alpha`, `alphanohtml` (chemins), `restricthtml` (mentions légales en textarea) — aucune donnée utilisateur passée brute à une requête SQL ou à `exec()`.
- Les valeurs `LEMONFACTURX_PHP_CLI_PATH` et `LEMONFACTURX_VERAPDF_PATH` passent par le filtre `alphanohtml` puis par la validation de `resolvePhpBinary()` à l'usage (double couche).
- Sortie HTML : les entrées dynamiques dans `$diagOk`/`$diagErrors` passent toutes par `dol_escape_htmltag()` avant concaténation. Aucune donnée contrôlée par un non-admin n'atteint la sortie brute.
- Les champs notes (`NOTE_PMD/PMT/AAB`) sont affichés dans un `<textarea>` via `dol_escape_htmltag()` — les balises HTML autorisées par `restricthtml` deviennent du texte littéral, pas du HTML exécuté.

**Aucune vulnérabilité identifiée.**

### 2.9 ✅ Chorus Pro (`generateChorusPdf`, `doActions`, `addMoreActionsButtons`)

**Mise à jour 22/06/2026 :** l'appel `exec()` de `generateChorusPdf()` a été supprimé au même titre que le flux principal. Les patterns de sécurité restants sont inchangés et corrects :
- Le chemin du PDF Chorus est dérivé du chemin du PDF principal via `preg_replace('/\.pdf$/i', '', $mainPdf).'-CHORUS.pdf'` — même origine contrôlée que 2.2.
- Le fichier XML temporaire Chorus (`tempnam()` + nettoyage `finally`) a été supprimé : le XML est passé en chaîne à `injectXmlIntoPdf()`.
- Action `lemonfacturx_generatechorus` soumise au même contrôle CSRF (`currentToken()`) et à la vérification de droit `userCanWrite()`.
- En cas d'échec, le PDF principal n'est **jamais** touché.
- `$phpBin` et `resolvePhpBinary()` supprimés de `generateChorusOnDemand()`.

**Aucune vulnérabilité identifiée.**

---

### 2.10 🟠 `chorus_tab.php` — logique CSRF incorrecte (`newToken()` vs `currentToken()`)

**Fichier :** `chorus_tab.php`, lignes 48 et 83.

```php
// Ligne 83 — formulaire : correct, embarque le token courant
print '<input type="hidden" name="token" value="'.newToken().'">';

// Ligne 48 — vérification POST : INCORRECT — newToken() régénère le token
if (GETPOST('token', 'alpha') !== newToken()) {
    accessforbidden('Bad value for CSRF token');
}
```

Dans le modèle Dolibarr, `newToken()` **génère et stocke un nouveau token**, tandis que `currentToken()` retourne le token actuellement valide pour vérification. La vérification correcte, utilisée partout ailleurs dans le module, compare le token soumis avec `currentToken()` :

```php
// admin/setup.php:44 — pattern correct
if (GETPOST('token', 'alpha') !== currentToken()) { ... }

// actions_lemonfacturx.class.php:386 — pattern correct
if (GETPOST('token', 'alpha') !== currentToken()) { ... }
```

**Conséquence selon le comportement de Dolibarr :**
- Si `newToken()` régénère systématiquement à chaque appel : la comparaison échoue toujours → toutes les sauvegardes de l'onglet Chorus Pro sont bloquées (briquage fonctionnel).
- Si `newToken()` retourne la même valeur dans la même requête : la protection CSRF est accidentellement correcte, mais uniquement par coïncidence et pas par design — fragile à tout changement de version de Dolibarr.

**Scénario d'exploitation (si CSRF inopérant) :** un attaquant peut faire déclencher par un utilisateur authentifié une requête POST vers `chorus_tab.php?action=savechorussettings`, modifiant les paramètres Chorus Pro (`LEMONFACTURX_CHORUS_*`) de l'instance sans que l'utilisateur en soit conscient.

**Correction :** remplacer `newToken()` par `currentToken()` à la ligne 48 :

```php
if (GETPOST('token', 'alpha') !== currentToken()) {
    accessforbidden('Bad value for CSRF token');
}
```

---

### 2.11 ✅ `core/lib/lemonfacturx.lib.php` — génération XML, requêtes SQL, appel HTTP

**Requêtes SQL :** toutes les valeurs interpolées sont castées `(int)` avant usage (lignes 492, 987, 1141, 1156, 1186, 1560). Aucune interpolation de chaîne utilisateur brute. **Pas d'injection SQL.**

**Génération XML :** toutes les valeurs injectées dans le XML passent par `lemonfacturx_xml_encode()`, qui appelle `htmlspecialchars(..., ENT_XML1 | ENT_QUOTES, 'UTF-8')`. **Pas d'injection XML.**

**Appel HTTP outbound (`lemonfacturx_check_latest_release()`) :**
- `CURLOPT_SSL_VERIFYPEER = true`, `CURLOPT_SSL_VERIFYHOST = 2` — TLS validé.
- `CURLOPT_TIMEOUT = 5` — appel borné.
- `tag_name` de la réponse n'est utilisé que dans `version_compare()` — jamais exécuté ou affiché brut.
- `html_url` de la réponse est validé par regex avant stockage en cache (`#^https://github\.com/hello-lemon/module-dolibarr-lemonfacturx/#`) et échappe via `dol_escape_htmltag()` à l'affichage.
- **Note :** la valeur `url` lue depuis le cache (`llx_const`) n'est pas re-validée par la regex — si un attaquant pouvait écrire dans `llx_const` (accès DB ou SQLi séparée), il pourrait injecter une URL arbitraire affichée dans `admin/setup.php`. Risque secondaire (nécessite un accès préalable) — **voir constat 2.14**.

**Fonction `lemonfacturx_invoice_pdf_path()` :** voir constat 2.12.

### 2.12 🟡 `core/lib/lemonfacturx.lib.php:1599` — Path traversal dans `lemonfacturx_invoice_pdf_path()` via `last_main_doc`

```php
function lemonfacturx_invoice_pdf_path($ref, $entity, $lastMainDoc = '')
{
    // Chemin principal — correctement sanitisé avec dol_sanitizeFileName($ref)
    $path = $dir.'/'.$safeRef.'/'.$safeRef.'.pdf';
    if (file_exists($path)) { return $path; }

    // Chemin de repli — INSUFFISAMMENT SANITISÉ
    if (!empty($lastMainDoc) && defined('DOL_DATA_ROOT')) {
        $candidate = DOL_DATA_ROOT.'/'.ltrim($lastMainDoc, '/');
        if (file_exists($candidate)) {
            return $candidate;
        }
    }
    return null;
}
```

Le `ltrim($lastMainDoc, '/')` ne supprime que les slashes initiaux. Une valeur comme `../../../../../../etc/passwd` (sans slash initial) traverse le filtre intact, produisant `DOL_DATA_ROOT/../../../../../../etc/passwd`. Aucun `realpath()` ni vérification que le chemin résolu reste sous `DOL_DATA_ROOT` n'est appliqué.

La valeur retournée est passée à `file_get_contents()` via `lemonfacturx_extract_xml_from_pdf()` (appels dans `api_lemonfacturx.class.php:101` et `actions_lemonfacturx.class.php:462`).

**Exploitabilité :** `last_main_doc` est écrit par Dolibarr lors de la génération PDF — pas d'entrée HTTP directe. Un attaquant doit disposer d'un accès en écriture sur `llx_facture.last_main_doc` (SQLi séparée, accès DB direct, ou permission Dolibarr permettant de manipuler ce champ) pour déclencher une lecture de fichier arbitraire. Exploitabilité faible en isolation, mais réelle si combinée avec une autre vulnérabilité.

**Recommandation :** ajouter une vérification de containment après résolution du chemin :

```php
$candidate = DOL_DATA_ROOT.'/'.ltrim($lastMainDoc, '/');
$real = realpath($candidate);
$base = realpath(DOL_DATA_ROOT);
if ($real !== false && $base !== false && strpos($real, $base.'/') === 0 && file_exists($real)) {
    return $real;
}
```

### 2.13 ✅ `class/api_lemonfacturx.class.php` — endpoints REST

**Authentification :** tous les endpoints passent par `loadInvoice()`, qui vérifie `hasRight('facture', 'lire')` puis `DolibarrApi::_checkAccessToResource('facture', $invoice->id)` (scope multicompany). Aucun endpoint non authentifié.

**Paramètres d'entrée :** l'ID de facture est casté `(int)` avant `Facture::fetch()` (ligne 125). Aucune interpolation brute dans une requête SQL.

**Données retournées :** l'endpoint `/xml` retourne le XML Factur-X complet (IBAN, SIREN, SIRET, adresses, lignes de facturation). C'est intentionnel et nécessaire pour Factur-X ; l'accès est correctement conditionné au droit `facture/lire`. À noter lors d'une revue de classification des données.

**`exec()` :** aucun appel shell déclenché par les endpoints API. La génération XML, la validation XSD et l'extraction depuis PDF utilisent uniquement des bibliothèques PHP.

**Path traversal hérité :** `getStatus()` (ligne 88) appelle `lemonfacturx_invoice_pdf_path()` avec `$invoice->last_main_doc` — voir constat 2.12.

### 2.14 🔵 Cache de version non re-validé (`lemonfacturx_check_latest_release()`)

```php
// Lecture depuis le cache llx_const (ligne ~1698)
$cached = json_decode(getDolGlobalString('LEMONFACTURX_LATEST_RELEASE_CACHE'), true);
$htmlUrl = $cached['url'] ?? '';
// ... affiché dans admin/setup.php via dol_escape_htmltag($updateInfo['url'])
```

La regex de validation de l'URL (`#^https://github\.com/hello-lemon/...#`) n'est appliquée qu'à la réponse HTTP en direct, pas à la valeur relue depuis le cache `llx_const`. Si un attaquant disposait d'un accès en écriture sur la table `llx_const` (SQLi séparée ou accès DB), il pourrait stocker une URL arbitraire affichée sur la page admin. Impact limité (admin-only, `dol_escape_htmltag()` empêche toute exécution de script) — risque résiduel purement informationnel dans le contexte de ce module.

**Recommandation :** appliquer la même validation regex à `$htmlUrl` quelle que soit son origine (live ou cache).

### 2.15 ✅ `core/modules/modLemonFacturX.class.php` — descripteur de module

- Hooks enregistrés : `pdfgeneration` et `invoicecard` uniquement — périmètre minimal et standard.
- Aucun identifiant ou secret codé en dur.
- `init()` / `remove()` délèguent à `$this->_init()` / `$this->_remove()` sans SQL personnalisé. `createChorusExtraFields()` utilise l'API `ExtraFields::addExtraField()` — pas de SQL brut.

**Aucune vulnérabilité identifiée.**

### 2.16 ✅ `demo/fixtures.php` et `demo/fixtures-rich.php`

- Garde `if (PHP_SAPI !== 'cli') { die('CLI only'); }` présente et correcte dans les deux fichiers.
- Toutes les requêtes SQL interpolent des valeurs soit castées `(int)`, soit passées par `$db->escape()`, soit issues de chaînes littérales — **pas d'injection SQL**.
- Connexion à la base Dolibarr réelle (via `master.inc.php`) — comportement attendu pour des scripts de fixtures.

**Aucune vulnérabilité identifiée.**

### 2.17 ✅ `core/lib/lemonfacturx_rules.php` — validateur BR-*

- `DOMDocument::loadXML()` appelé sans `LIBXML_NOENT` ni `LIBXML_DTDLOAD`.
- `libxml_use_internal_errors(true)` activé avant l'appel, erreurs collectées et vidées proprement.
- Le paramètre `$xml` reçu par `lemonfacturx_validate_xsd()` et `lemonfacturx_validate_business_rules()` est dans tous les cas soit généré par `lemonfacturx_build_xml()` (valeurs sanitisées via `htmlspecialchars(ENT_XML1)`), soit extrait d'un PDF sur disque — jamais issu d'une entrée HTTP directe.
- En PHP 8.0+, le chargement d'entités externes est désactivé par défaut dans `loadXML()` — XXE non exploitable sur ces versions.
- Sur PHP 7.4 (minimum déclaré dans `composer.json`), `loadXML()` charge les entités externes par défaut et `libxml_disable_entity_loader(true)` n'est **pas** appelé dans ce fichier. Voir constat 2.18.

**Aucune vulnérabilité identifiée sur PHP ≥ 8.0. Voir constat 2.18 pour PHP 7.4.**

### 2.18 ✅ Protection XXE absente pour PHP < 8.0 (`lemonfacturx_rules.php`) — **RÉSOLU**

Le module supporte PHP 7.4+ (`composer.json` : `"php": "^7.4||^8.0"`). Sur PHP < 8.0, `DOMDocument::loadXML()` charge les entités externes par défaut. `libxml_disable_entity_loader(true)` n'est pas appelé dans `lemonfacturx_rules.php`.

**Exploitabilité :** le XML parsé est soit généré par le module lui-même (`lemonfacturx_build_xml()`), soit extrait d'un PDF sur disque via `lemonfacturx_extract_xml_from_pdf()`. Un PDF contenant un XML avec des entités externes malveillantes (XXE) pourrait déclencher une lecture de fichier arbitraire côté serveur lors de la validation, sur les instances tournant sous PHP < 8.0.

**Recommandation :** ajouter la protection dans `lemonfacturx_validate_xsd()` et `lemonfacturx_validate_business_rules()` avant tout appel à `loadXML()` :

```php
if (PHP_MAJOR_VERSION < 8 && function_exists('libxml_disable_entity_loader')) {
    libxml_disable_entity_loader(true);
}
```

*Note : `libxml_disable_entity_loader()` est déprécié en PHP 8.0 (sans effet, la protection est native) mais son appel conditionnel sur PHP 7.x est sans risque.*

### 2.19 🔵 Injection in-process — changement de modèle d'isolation (22/06/2026)

Le passage de `exec(inject_facturx.php)` à `\Atgp\FacturX\Writer::generate()` in-process modifie le modèle de menace de l'injection PDF :

| Aspect | Ancien modèle (subprocess) | Nouveau modèle (in-process) |
|---|---|---|
| Crash sur PDF/XML pathologique | Isole le process CLI, la requête web continue | Lève une `\Throwable` catchée dans `injectXmlIntoPdf()` |
| Exhaustion mémoire | Limitée au process CLI (ulimit séparé) | Affecte directement le process web (FPM worker) |
| `max_execution_time` | Ne couvre pas le temps `exec()` | Couvre l'appel Writer normalement |
| Conflit de classe FPDF | Nécessitait l'isolation du subprocess | Résolu par renommage `SetasignFPDF` (patches/) |

Le `try/catch(\Throwable)` dans `injectXmlIntoPdf()` protège contre les exceptions. Le risque résiduel est une exhaustion mémoire sur PDF très volumineux, couvert par le constat 2.5.

**Aucune nouvelle vulnérabilité exploitable identifiée.** Le modèle in-process est standard pour les bibliothèques PDF PHP (TCPDF, mPDF, etc.) et considéré acceptable dans ce contexte.

---

## 3. Synthèse des recommandations, par priorité

| # | Constat | Priorité | Action |
|---|---|---|---|
| 2.10 | CSRF `chorus_tab.php` — `newToken()` → `currentToken()` | 🟠 Moyenne | Corriger ligne 48 de `chorus_tab.php` |
| 2.12 | Path traversal `last_main_doc` — pas de `realpath()` containment | 🟡 Faible | Ajouter vérification `str_starts_with(realpath(...), realpath(DOL_DATA_ROOT))` |
| 2.5 | Pas de contrôle taille/signature avant chargement PDF in-process | 🟡 Faible | Ajouter garde-fou dans `injectXmlIntoPdf()` avant `file_get_contents()` |
| 2.19 | Injection in-process — changement de modèle d'isolation | 🔵 Info | Pris en compte via 2.5 ; aucune action bloquante |
| ~~2.18~~ | ~~Protection XXE absente pour PHP < 8.0~~ | ✅ Résolu | `libxml_disable_entity_loader(true)` ajouté dans les deux fonctions `loadXML()` |
| 2.14 | URL de mise à jour non re-validée depuis le cache | 🔵 Info | Appliquer la regex de validation aussi sur la lecture de cache |
| 2.6 | Dépendance à `.htaccess` (inopérant sous Nginx) | 🔵 Info | Vérifier la config serveur réelle |
| ~~2.3~~ | ~~Portée admin de `LEMONFACTURX_PHP_CLI_PATH`~~ | ✅ Résolu | `resolvePhpBinary()` supprimé, paramètre inutilisé |
| ~~2.4~~ | ~~Pas de timeout sur les subprocessus d'injection~~ | ✅ Résolu | Subprocessus d'injection supprimés |
| ~~1.1~~ | ~~FPDI CVE-2026-45802~~ | ✅ Résolu | FPDI mis à jour en 2.6.8 |
| ~~1.2~~ | ~~FPDF CVE-2025-65875~~ | ✅ Résolu | FPDF mis à jour en 1.9.0 |
| ~~1.3~~ | ~~Absence de composer.lock~~ | ✅ Résolu | composer.lock ajouté |
| ~~1.4~~ | ~~Workflow release sans `composer install`~~ | ✅ Résolu | `composer install --no-dev` intégré au workflow |

---

## 4. Couverture de l'audit

### Fichiers couverts

| Fichier | Statut | Date |
|---|---|---|
| `scripts/inject_facturx.php` | ✅ Supprimé | Script supprimé le 22/06/2026 — injection migrée in-process (`injectXmlIntoPdf()`) |
| `class/actions_lemonfacturx.class.php` | ✅ Couvert | Audit initial + mise à jour 22/06/2026 |
| `admin/setup.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `chorus_tab.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `core/lib/lemonfacturx.lib.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `core/lib/lemonfacturx_rules.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `class/api_lemonfacturx.class.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `core/modules/modLemonFacturX.class.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `demo/fixtures.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `demo/fixtures-rich.php` | ✅ Couvert | Mise à jour 21/06/2026 |
| `scripts/export_facturx_batch.php` | ✅ Couvert | Mise à jour 21/06/2026 |

### Périmètre non couvert

- `vendor/atgp/factur-x` v3.3.0 — code de la lib elle-même, au-delà de ses CVE publiées
- Tests dynamiques (fuzzing du XML/PDF en entrée, test d'intrusion)
- Vérification empirique de la présence et de l'efficacité des fichiers `.htaccess` sur une instance réelle

---

*Rapport généré à partir d'une revue de code statique et de recherches de vulnérabilités publiques. Ne remplace pas un audit de sécurité professionnel formel, en particulier avant un déploiement traitant des données de facturation réelles à grande échelle.*
