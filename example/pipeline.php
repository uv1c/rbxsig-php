#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use RobloxSigner\Keys\KeyGenerationRequest;
use RobloxSigner\Keys\KeyGenerationService;
use RobloxSigner\Keys\KeySize;
use RobloxSigner\Keys\OutputFileNames;
use RobloxSigner\SignatureFormat;
use RobloxSigner\Signer;
use RobloxSigner\Verifier;

$directory = sys_get_temp_dir()
    . DIRECTORY_SEPARATOR
    . 'rbxsig-pipeline-'
    . bin2hex(random_bytes(4));

$fileNames = OutputFileNames::fromDirectory($directory);
$service = KeyGenerationService::create();

try {
    $keyPair = $service->generate(
        new KeyGenerationRequest(KeySize::bits2048(), $fileNames)
    );

    $script = "print('signed with the generated key')\n";
    $signed = Signer::signWithPem(
        $script,
        $keyPair->getPrivateKeyPem(),
        SignatureFormat::RBXSIG2
    );

    $valid = Verifier::verify($signed, $keyPair->getPublicKeyPem());

    echo "Generated keys in: {$directory}\n";
    echo 'Signature valid: ' . ($valid ? 'yes' : 'no') . "\n";
    echo "Signed output:\n{$signed}\n";
} finally {
    // This is a demo: do not leave a private key behind in a temp directory.
    @unlink($fileNames->getPrivateKey());
    @unlink($fileNames->getPublicKey());
    @unlink($fileNames->getPublicKeyBlob());
    @rmdir($directory);

    echo "Temporary key files removed.\n";
}
