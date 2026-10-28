<?php
/*
 * Tests PHPUnit — vérification du patch FPDF/FPDI et injection inline Factur-X.
 *
 * Objectifs :
 *  1. La classe FPDF globale peut coexister avec SetasignFPDF (simulation du
 *     contexte Dolibarr où FPDF est déjà défini par le cœur).
 *  2. FpdfTpl hérite bien de SetasignFPDF (patch fpdi.patch appliqué).
 *  3. ActionsLemonFacturX::injectXmlIntoPdf() s'exécute dans le même process
 *     sans conflit de classe — le raison d'être du renommage.
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../class/actions_lemonfacturx.class.php';

/**
 * Expose injectXmlIntoPdf() (protected) pour les tests.
 */
class TestableActionsLemonFacturX extends ActionsLemonFacturX
{
    public function injectXmlIntoPdfPublic(string $pdfPath, string $xml, string $modulePath): ?string
    {
        return $this->injectXmlIntoPdf($pdfPath, $xml, $modulePath);
    }
}

class FpdfPatchTest extends TestCase
{
    /** @var string|null */
    private $tmpPdf = null;

    protected function tearDown(): void
    {
        if ($this->tmpPdf !== null && file_exists($this->tmpPdf)) {
            unlink($this->tmpPdf);
            $this->tmpPdf = null;
        }
    }

    public function testSetasignFpdfClassIsRenamed(): void
    {
        $this->assertTrue(
            class_exists('SetasignFPDF'),
            'SetasignFPDF doit exister après application du patch fpdf.patch'
        );
    }

    public function testDolibarrFpdfClassCoexists(): void
    {
        $this->assertTrue(class_exists('FPDF'), 'La classe FPDF de Dolibarr doit rester accessible');
        $dolibarr = new FPDF();
        $this->assertSame('dolibarr', $dolibarr->dolibarrCoreMethod());
    }

    public function testFpdfTplExtendsSetasignFpdf(): void
    {
        $this->assertTrue(
            is_subclass_of('setasign\Fpdi\FpdfTpl', 'SetasignFPDF'),
            'FpdfTpl doit hériter de SetasignFPDF (patch fpdi.patch appliqué)'
        );
    }

    public function testWriterCanBeInstantiated(): void
    {
        $writer = new \Atgp\FacturX\Writer();
        $this->assertInstanceOf(\Atgp\FacturX\Writer::class, $writer);
    }

    public function testInjectXmlIntoPdfWritesFacturxInProcess(): void
    {
        // Génère un PDF minimal avec SetasignFPDF et l'écrit sur disque.
        $fpdf = new SetasignFPDF();
        $fpdf->AddPage();
        $fpdf->SetFont('Helvetica', '', 12);
        $fpdf->Cell(0, 10, 'Test LemonFacturX');
        $this->tmpPdf = tempnam(sys_get_temp_dir(), 'lfx_test_') . '.pdf';
        file_put_contents($this->tmpPdf, $fpdf->Output('S'));

        $this->assertStringStartsWith('%PDF', file_get_contents($this->tmpPdf), 'Le PDF initial doit être valide');

        // Génère un XML Factur-X EN16931 valide via les stubs (même chemin que
        // les tests unitaires existants).
        $GLOBALS['lfx_test_conf'] = [
            'LEMONFACTURX_BANK_ACCOUNT'  => 0,
            'LEMONFACTURX_PAYMENT_MEANS' => '30',
        ];
        $mysoc          = lfx_make_party(['name' => 'LEMON SASU', 'idprof1' => '909458306', 'idprof2' => '90945830600012', 'tva_intra' => 'FR38909458306']);
        $invoice        = new LfxFakeInvoice();
        $invoice->ref   = 'FA2606-TEST';
        $invoice->thirdparty = lfx_make_party();
        $invoice->lines = [lfx_make_line(1000.00, 20.0, 200.00)];
        $invoice->total_ht  = 1000.00;
        $invoice->total_tva = 200.00;
        $invoice->total_ttc = 1200.00;
        $buildWarnings  = [];
        $xml = lemonfacturx_build_xml($invoice, $mysoc, $buildWarnings);

        $this->assertNotEmpty($xml, 'lemonfacturx_build_xml() doit retourner un XML');

        $modulePath = dirname(__DIR__);
        $subject = new TestableActionsLemonFacturX(null);
        $error = $subject->injectXmlIntoPdfPublic($this->tmpPdf, $xml, $modulePath);

        $this->assertNull($error, 'injectXmlIntoPdf() ne doit pas retourner d\'erreur : '.$error);

        $result = file_get_contents($this->tmpPdf);
        $this->assertStringStartsWith('%PDF', $result, 'Le PDF résultant doit être valide');
        $this->assertStringContainsString('factur-x.xml', $result, 'Le PDF doit contenir la pièce jointe Factur-X');
    }
}
