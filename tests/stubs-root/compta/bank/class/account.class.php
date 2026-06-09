<?php
/*
 * Stub de la classe Account Dolibarr pour les tests unitaires standalone.
 * Renvoie le compte défini dans $GLOBALS['lfx_test_bank'] (ou échec si absent).
 */
if (!class_exists('Account')) {
	class Account
	{
		public $iban = '';
		public $bic = '';

		public function __construct($db)
		{
		}

		public function fetch($id)
		{
			$bank = $GLOBALS['lfx_test_bank'] ?? null;
			if (!$bank) {
				return 0;
			}
			$this->iban = $bank['iban'] ?? '';
			$this->bic = $bank['bic'] ?? '';
			return 1;
		}
	}
}
