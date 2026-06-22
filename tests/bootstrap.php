<?php
/*
 * Bootstrap PHPUnit — chargé une seule fois avant tous les tests.
 *
 * Définit la classe FPDF globale AVANT l'autoloader pour simuler le contexte
 * Dolibarr (le cœur charge son propre FPDF avant que ce module ne soit actif).
 * Sans le patch fpdf.patch, ceci provoquerait "Cannot redeclare class FPDF".
 */

if (!class_exists('FPDF')) {
    class FPDF
    {
        public function dolibarrCoreMethod(): string
        {
            return 'dolibarr';
        }
    }
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/stubs.php';
require_once __DIR__ . '/../core/lib/lemonfacturx.lib.php';
require_once __DIR__ . '/../core/lib/lemonfacturx_rules.php';
