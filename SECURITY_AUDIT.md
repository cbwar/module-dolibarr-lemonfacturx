# Rapport de sécurité — Module LemonFacturX (Dolibarr)

**Cible auditée :** `hello-lemon/module-dolibarr-lemonfacturx`
**Version analysée :** 3.0.0 / 3.2.1 (dernière release au 16 juin 2026)
**Contexte :** module complémentaire Dolibarr pour la génération de factures Factur-X EN16931, déployé en environnement self-hosted (Dolibarr 21)
**Méthode :** revue de code manuelle (fichiers `inject_facturx.php`, `actions_lemonfacturx.class.php`), recherche de CVE sur les dépendances vendored, analyse de la documentation publique (README, SECURITY.md)
**Limites :** revue partielle — fichiers `admin/setup.php`, `core/lib/lemonfacturx.lib.php`, `core/lib/lemonfacturx_rules.php` et la section Chorus Pro (lignes 215-474 de `actions_lemonfacturx.class.php`) non couverts par cette analyse. Aucun test dynamique (fuzzing, pentest) effectué.

---

## Résumé exécutif

Le module présente un **niveau de maturité sécurité supérieur à la moyenne** des modules communautaires Dolibarr : échappement systématique des arguments shell, validation des chemins de binaires, isolation des scripts CLI, écriture atomique des fichiers. Aucune vulnérabilité d'injection de commande ou de path traversal n'a été identifiée dans le code propre au module.

**Le risque principal identifié est externe au code du module** : une dépendance vendored (`setasign/fpdi` v2.6.6) est concernée par une vulnérabilité de déni de service publiée après son intégration. Le mode de distribution sans Composer (dépendances figées et commitées) signifie que ce risque ne sera pas corrigé automatiquement et dépend de la réactivité du mainteneur.

| Sévérité | Nombre de constats |
|---|---|
| 🔴 Élevée | 0 |
| 🟠 Moyenne | 2 |
| 🟡 Faible | 4 |
| 🔵 Informative | 3 |

---

## 1. Constats — Dépendances vendored

### 1.1 🟠 `setasign/fpdi` v2.6.6 — DoS par épuisement mémoire (CWE-770)

**CVE-2026-45802** (GHSA-2mgw-7q6p-8grg), sévérité **MODERATE** (CVSS 4.0 : 6.0).

> Prior to version 2.6.7, an attacker can upload a small, malicious PDF file that will cause the server-side script to crash due to memory exhaustion or a script time-out. Repeated attacks can lead to sustained service unavailability.

La version vendored par LemonFacturX est **2.6.6** — donc **vulnérable**. Le correctif existe en 2.6.7.

**Applicabilité dans ce contexte :** le scénario d'exploitation classique ("upload d'un PDF malveillant par un utilisateur non fiable") est partiellement atténué ici car FPDI n'est pas exposé à des PDF *uploadés librement* par un visiteur anonyme — il traite le PDF déjà généré par Dolibarr lui-même (`afterPDFCreation`). Le vecteur d'attaque le plus réaliste serait donc :
- un **template de facture PDF personnalisé** (tiers ou custom) produisant un PDF malformé qui déclenche le bug en aval lors de l'injection Factur-X ;
- ou un acteur ayant déjà un accès en écriture aux documents Dolibarr (donc déjà un niveau de compromission significatif).

Le risque reste réel mais le niveau de privilège requis pour l'exploiter dans ce pipeline précis est plus élevé que dans le cas d'usage générique de la CVE.

**Recommandation :** mettre à jour `vendor/setasign/fpdi` vers ≥ 2.6.7 dans l'installation locale, en attendant une release officielle du module qui l'embarque.

*Note connexe (non bloquante pour ce module) :* une CVE antérieure sur le même CWE existe aussi — **CVE-2025-54869**, corrigée en 2.6.3 — donc déjà couverte par la version 2.6.6 vendored ; seule la 2026-45802 (fix en 2.6.7) reste ouverte.

### 1.2 🟡 `setasign/fpdf` 1.8.6 — upload de fichier arbitraire via `AddFont()`

**CVE-2025-65875**, sévérité **HIGH** (CVSS 3.1 : 8.8).

> An arbitrary file upload vulnerability in the AddFont() function of FPDF v1.86 and earlier allows attackers to execute arbitrary code via uploading a crafted PHP file.

La version vendored (1.8.6) correspond exactement à la version citée comme affectée dans les bases CVE consultées.

**Applicabilité :** ce vecteur dépend de l'appel à la fonction `AddFont()` avec un nom de fichier influençable par un attaquant. Le module LemonFacturX ne semble pas, d'après le code revu, exposer de mécanisme permettant à un utilisateur de contrôler dynamiquement un chemin de police passé à FPDF — mais cette hypothèse **n'a pas été vérifiée** dans le code de `atgp/factur-x` lui-même (hors périmètre de cette revue, fichier non fourni). À vérifier avant de l'écarter formellement.

**Recommandation :** vérifier si `atgp/factur-x` v3.3.0 appelle `AddFont()` avec un paramètre dérivé d'une donnée de facture (police custom, langue, etc.). Si non utilisé, le risque est theoretical only dans ce pipeline. Mettre à jour si un correctif FPDF existe au-delà de 1.8.6.

### 1.3 🔵 Absence de `composer.lock` / mécanisme d'audit automatisé

Le module distribue ses dépendances en `vendor/` pré-rempli et commité, sans `composer.json` exploitable par l'utilisateur final (cf. README : *"pas de Composer requis sur le serveur"*).

**Conséquence sécurité :** aucun outil standard (`composer audit`, Dependabot, Snyk) ne peut surveiller automatiquement ces dépendances dans l'installation Dolibarr de l'utilisateur. La détection de CVE futures dépend entièrement de la veille du mainteneur du module et de sa réactivité à republier une release.

**Recommandation :** ajouter aux tâches périodiques de maintenance de votre instance un contrôle manuel trimestriel des versions présentes dans `vendor/` face à la base CVE (ou exécuter `composer audit` dans un environnement de test isolé reproduisant le contenu du `vendor/`).

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

### 2.4 🟡 Absence de timeout shell sur le subprocess principal d'injection

```php
exec($cmd, $output, $returnCode); // pas de wrapper "timeout"
```

À comparer avec `runVeraPdf()`, qui utilise explicitement un timeout :
```php
if (is_executable('/usr/bin/timeout')) {
    $cmd = '/usr/bin/timeout 60 '.$cmd;
}
```

Le subprocess principal (`inject_facturx.php`, qui appelle `atgp/factur-x`) n'a **pas** cette protection. En cas de XML ou PDF pathologique non intercepté par la validation XSD amont, un blocage du subprocess pourrait laisser un process PHP CLI orphelin, et potentiellement geler la requête HTTP appelante (selon configuration de `max_execution_time`, qui ne couvre pas le temps passé dans `exec()`).

**Recommandation :** appliquer la même protection `timeout` (ou équivalent portable) au subprocess `inject_facturx.php` que celle déjà en place pour veraPDF.

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

---

## 3. Synthèse des recommandations, par priorité

| # | Constat | Priorité | Action |
|---|---|---|---|
| 1.1 | FPDI 2.6.6 vulnérable (CVE-2026-45802) | 🟠 Moyenne | Mettre à jour vers FPDI ≥ 2.6.7 dans `vendor/` |
| 1.2 | FPDF 1.8.6 — CVE-2025-65875 (upload arbitraire via `AddFont`) | 🟡 Faible | Vérifier l'usage réel de `AddFont()` dans `atgp/factur-x` ; mettre à jour si applicable |
| 2.4 | Pas de timeout sur le subprocess principal | 🟡 Faible | Aligner sur le traitement déjà fait pour veraPDF |
| 2.5 | Pas de contrôle taille/signature avant lecture PDF/XML | 🟡 Faible | Ajouter un garde-fou avant `file_get_contents()` |
| 2.3 | Portée admin de `LEMONFACTURX_PHP_CLI_PATH` | 🟡 Faible | Restreindre/documenter en contexte multi-admin |
| 2.6 | Dépendance à `.htaccess` (inopérant sous Nginx) | 🔵 Info | Vérifier la config serveur réelle |
| 1.3 | Pas d'audit automatisé des dépendances vendored | 🔵 Info | Contrôle manuel périodique recommandé |

---

## 4. Ce qui n'a **pas** été couvert par cet audit

- `admin/setup.php` (page de configuration, gestion CSRF du formulaire admin)
- `core/lib/lemonfacturx.lib.php` et `lemonfacturx_rules.php` (génération XML, validation des règles métier)
- La section Chorus Pro (`generateChorusPdf` et suite, lignes ~215-474 du fichier d'actions)
- `class/api_lemonfacturx.class.php` (endpoints API REST)
- Le contenu réel de `atgp/factur-x` v3.3.0 (la lib elle-même, pas seulement ses CVE publiées)
- Tests dynamiques (fuzzing du XML/PDF en entrée, test d'intrusion)
- Vérification empirique de la présence et de l'efficacité des fichiers `.htaccess` sur une instance réelle

---

*Rapport généré à partir d'une revue de code statique et de recherches de vulnérabilités publiques. Ne remplace pas un audit de sécurité professionnel formel, en particulier avant un déploiement traitant des données de facturation réelles à grande échelle.*
