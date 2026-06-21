# Rapport de sécurité — Module LemonFacturX (Dolibarr)

**Cible auditée :** `hello-lemon/module-dolibarr-lemonfacturx`
**Version analysée :** 3.5.0 (dernière release), branch `main` au 21 juin 2026
**Contexte :** module complémentaire Dolibarr pour la génération de factures Factur-X EN16931, déployé en environnement self-hosted (Dolibarr 21)
**Méthode :** revue de code manuelle (fichiers `inject_facturx.php`, `actions_lemonfacturx.class.php` intégralité, `admin/setup.php`), recherche de CVE sur les dépendances (composer.lock), analyse de la documentation publique (README, SECURITY.md)
**Limites :** revue partielle — fichiers `core/lib/lemonfacturx.lib.php`, `core/lib/lemonfacturx_rules.php` et `class/api_lemonfacturx.class.php` non couverts. Aucun test dynamique (fuzzing, pentest) effectué.

---

## Résumé exécutif

Le module présente un **niveau de maturité sécurité supérieur à la moyenne** des modules communautaires Dolibarr : échappement systématique des arguments shell, validation des chemins de binaires, isolation des scripts CLI, écriture atomique des fichiers. Aucune vulnérabilité d'injection de commande ou de path traversal n'a été identifiée dans le code propre au module.

**Les CVE identifiées sur les dépendances (FPDI, FPDF) ont été résolues** par la migration vers Composer (ajout de `composer.json` + `composer.lock`, 21 juin 2026). Le risque résiduel principal est opérationnel : le workflow de release n'a pas encore été mis à jour pour exécuter `composer install`, rendant toute release publiée dans l'état actuel non installable (constat 1.4).

| Sévérité | Nombre de constats |
|---|---|
| 🔴 Élevée | 0 |
| 🟠 Moyenne | 1 |
| 🟡 Faible | 3 |
| 🔵 Informative | 2 |
| ✅ Résolu depuis audit initial | 3 |

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

### 1.4 🟠 Workflow de release non aligné sur le nouveau modèle Composer

Depuis le retrait de `vendor/` du dépôt, le workflow `.github/workflows/release-zip.yml` n'exécute pas `composer install --no-dev` avant de construire l'archive. Un tag publié dans cet état produirait un ZIP sans dépendances, incompatible avec toute installation Dolibarr (erreur `require_once … atgp/factur-x …` au premier appel du hook).

**Risque :** indisponibilité complète du module pour les utilisateurs qui installeraient la release défectueuse.

**Recommandation :** ajouter dans `build-zip` avant l'étape `rsync`, après le checkout :

```yaml
- name: Install Composer dependencies (no dev)
  run: composer install --no-dev --optimize-autoloader
```

et s'assurer que le `rsync` inclut bien `vendor/` dans l'archive (il n'est pas dans la liste `--exclude`).

---

## 2. Constats — Code propre au module

### 2.1 ✅ Construction de la commande `exec()` (`actions_lemonfacturx.class.php`)

```php
$cmd  = escapeshellarg($phpBin);
$cmd .= ' '.escapeshellarg($modulePath.'/scripts/inject_facturx.php');
$cmd .= ' '.escapeshellarg($file);
$cmd .= ' '.escapeshellarg($this->xmlTmpFile);
```

Tous les arguments passent par `escapeshellarg()`, y compris ceux dérivés de données métier (`$file`). **Aucune injection de commande shell identifiée.**

### 2.2 ✅ Origine des chemins de fichiers

- `$file` provient de `$parameters['file']`, fourni par le hook Dolibarr core `afterPDFCreation` — pas d'entrée utilisateur directe.
- `$this->xmlTmpFile` est généré par `tempnam()` dans `DOL_DATA_ROOT/facturx/temp/` — nom aléatoire, répertoire fixe.

**Aucun path traversal identifié** sur ces deux paramètres dans le code revu.

### 2.3 🟠 Validation de `LEMONFACTURX_PHP_CLI_PATH` — défense en profondeur correcte, mais surface résiduelle

```php
if (!preg_match('#^[A-Za-z0-9/._:() \\\\-]+$#', $phpBin)) { /* refus */ }
if (strpos($phpBin, '/') !== false && !is_executable($phpBin)) { /* refus */ }
```

La regex whitelist exclut les métacaractères shell dangereux. Combinée à `escapeshellarg()` en aval, la protection est en couches (defense in depth), ce qui est une bonne pratique.

**Point d'attention :** cette constante est modifiable par tout compte ayant accès à `/admin/const.php` de Dolibarr — c'est-à-dire **tout compte avec droits admin global**, pas seulement un admin du module LemonFacturX spécifiquement. Dans un Dolibarr multi-admin, ça élargit légèrement la surface de confiance nécessaire à ce paramètre. C'est un comportement standard Dolibarr (pas un défaut du module), mais à garder en tête dans un contexte multi-utilisateurs.

**Recommandation :** dans un déploiement avec plusieurs comptes admin, documenter que la modification de `LEMONFACTURX_PHP_CLI_PATH` doit être réservée à l'équipe technique.

### 2.4 🟡 Absence de timeout shell sur les subprocessus d'injection

```php
exec($cmd, $output, $returnCode); // pas de wrapper "timeout"
```

À comparer avec `runVeraPdf()`, qui utilise explicitement un timeout :
```php
if (is_executable('/usr/bin/timeout')) {
    $cmd = '/usr/bin/timeout 60 '.$cmd;
}
```

Le subprocess principal (`inject_facturx.php`) et le subprocess Chorus (`generateChorusPdf()`) n'ont **pas** cette protection. En cas de XML ou PDF pathologique non intercepté par la validation XSD amont, un blocage du subprocess pourrait laisser un process PHP CLI orphelin et potentiellement geler la requête HTTP appelante (`max_execution_time` ne couvre pas le temps passé dans `exec()`). Le risque est le même sur les deux appels.

**Recommandation :** appliquer la même protection `timeout` (ou équivalent portable) aux deux subprocessus `inject_facturx.php` (injection principale et Chorus) que celle déjà en place pour veraPDF.

### 2.5 🟡 `inject_facturx.php` — absence de contrôle de type/taille avant lecture

```php
$pdfContent = file_get_contents($pdfPath);
$xmlContent = file_get_contents($xmlPath);
```

Pas de vérification de la signature de fichier (`%PDF-`) ni de limite de taille avant chargement intégral en mémoire. Risque mineur de déni de service local si un fichier anormalement volumineux se retrouve à ce stade (peu probable compte tenu de l'origine contrôlée des fichiers, cf. 2.2, mais defense-in-depth absente).

**Recommandation :** ajouter une vérification de taille maximale et de signature de fichier avant `file_get_contents()`.

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

Le `try/finally` autour du hook garantit la suppression du fichier XML temporaire même en cas d'exception. Écriture atomique (`tempnam` + `rename`) appliquée de façon cohérente dans `inject_facturx.php` et dans le flux principal. Bonne robustesse générale face aux échecs partiels.

### 2.8 ✅ `admin/setup.php` — contrôles d'accès et sanitisation des entrées

Couvert dans cette mise à jour. Constats :
- Garde d'accès `if (!$user->admin) { accessforbidden(); }` en tête de fichier.
- CSRF vérifié sur toutes les actions POST (`GETPOST('token', 'alpha') !== currentToken()`), y compris l'action `setforcefont`.
- Entrées filtrées avec les helpers Dolibarr appropriés : `GETPOSTINT`, `alpha`, `alphanohtml` (chemins), `restricthtml` (mentions légales en textarea) — aucune donnée utilisateur passée brute à une requête SQL ou à `exec()`.
- Les valeurs `LEMONFACTURX_PHP_CLI_PATH` et `LEMONFACTURX_VERAPDF_PATH` passent par le filtre `alphanohtml` puis par la validation de `resolvePhpBinary()` à l'usage (double couche).

**Aucune vulnérabilité identifiée.**

### 2.9 ✅ Chorus Pro (`generateChorusPdf`, `doActions`, `addMoreActionsButtons`)

Couvert dans cette mise à jour. La section Chorus Pro (lignes 207-366 de `actions_lemonfacturx.class.php`) reproduit fidèlement les mêmes patterns de sécurité que le flux principal :
- Arguments `exec()` systématiquement passés par `escapeshellarg()` — **aucune injection de commande identifiée**.
- Le chemin du PDF Chorus est dérivé du chemin du PDF principal via `preg_replace('/\.pdf$/i', '', $mainPdf).'-CHORUS.pdf'` — même origine contrôlée que 2.2, pas d'entrée utilisateur directe.
- Fichier XML temporaire Chorus écrit dans `DOL_DATA_ROOT/facturx/temp/` avec `tempnam()` + nettoyage `finally` — même modèle que le flux standard.
- Action `lemonfacturx_generatechorus` soumise au même contrôle CSRF (`currentToken()`) et à la vérification de droit `userCanWrite()` que les autres actions de la fiche facture.
- En cas d'échec, le PDF principal n'est **jamais** touché (garantie documentée et vérifiée dans le code).

**Seul écart identifié :** absence de timeout sur le subprocess Chorus — couvert par le constat 2.4 ci-dessus.**

---

## 3. Synthèse des recommandations, par priorité

| # | Constat | Priorité | Action |
|---|---|---|---|
| 1.4 | Workflow `release-zip.yml` non mis à jour pour Composer | 🟠 Moyenne | Ajouter `composer install --no-dev` avant le `rsync` |
| 2.4 | Pas de timeout sur les subprocessus d'injection (principal + Chorus) | 🟡 Faible | Aligner sur le traitement déjà fait pour veraPDF |
| 2.5 | Pas de contrôle taille/signature avant lecture PDF/XML | 🟡 Faible | Ajouter un garde-fou avant `file_get_contents()` |
| 2.3 | Portée admin de `LEMONFACTURX_PHP_CLI_PATH` | 🟡 Faible | Documenter en contexte multi-admin |
| 2.6 | Dépendance à `.htaccess` (inopérant sous Nginx) | 🔵 Info | Vérifier la config serveur réelle |
| 1.3 | Transition modèle Composer en cours (WIP) | 🔵 Info | Voir 1.4 ; vérifier avant prochain tag |
| ~~1.1~~ | ~~FPDI CVE-2026-45802~~ | ✅ Résolu | FPDI mis à jour en 2.6.8 |
| ~~1.2~~ | ~~FPDF CVE-2025-65875~~ | ✅ Résolu | FPDF mis à jour en 1.9.0 |
| ~~1.3~~ | ~~Absence de composer.lock~~ | ✅ Résolu | composer.lock ajouté |

---

## 4. Ce qui n'a **pas** été couvert par cet audit

- `core/lib/lemonfacturx.lib.php` et `lemonfacturx_rules.php` (génération XML, validation des règles métier)
- `class/api_lemonfacturx.class.php` (endpoints API REST — droits, filtrage des entrées, exposition de données)
- Le contenu réel de `atgp/factur-x` v3.3.0 (la lib elle-même, pas seulement ses CVE publiées)
- Tests dynamiques (fuzzing du XML/PDF en entrée, test d'intrusion)
- Vérification empirique de la présence et de l'efficacité des fichiers `.htaccess` sur une instance réelle

**Couvert lors de la mise à jour du 21 juin 2026 (périmètre initialement exclu) :**
- `admin/setup.php` intégralité — voir constat 2.8
- Section Chorus Pro de `actions_lemonfacturx.class.php` (`generateChorusPdf`, `generateChorusOnDemand`, `doActions`, `addMoreActionsButtons`) — voir constat 2.9

---

*Rapport généré à partir d'une revue de code statique et de recherches de vulnérabilités publiques. Ne remplace pas un audit de sécurité professionnel formel, en particulier avant un déploiement traitant des données de facturation réelles à grande échelle.*
