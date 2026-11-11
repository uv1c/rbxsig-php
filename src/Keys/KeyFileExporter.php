<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use RuntimeException;

final class KeyFileExporter
{
    public function __construct(private readonly FileWriter $fileWriter)
    {
    }

    public function exportKeyPair(
        KeyPair $keyPair,
        OutputFileNames $fileNames,
        bool $overwrite = false
    ): void {
        $paths = [
            $fileNames->getPrivateKey(),
            $fileNames->getPublicKey(),
            $fileNames->getPublicKeyBlob(),
        ];

        if (!$overwrite) {
            foreach ($paths as $path) {
                if (file_exists($path)) {
                    throw new RuntimeException("Refusing to overwrite existing file: {$path}");
                }
            }
        }

        // Write public material first. The private key is written last, so an
        // interrupted run does not leave a private key without its public pair.
        $this->fileWriter->write(
            $fileNames->getPublicKey(),
            $keyPair->getPublicKeyPem(),
            $overwrite
        );
        $this->fileWriter->write(
            $fileNames->getPublicKeyBlob(),
            $keyPair->getPublicKeyBlobBase64(),
            $overwrite
        );
        $this->fileWriter->writeOwnerOnly(
            $fileNames->getPrivateKey(),
            $keyPair->getPrivateKeyPem(),
            $overwrite
        );
    }
}
