<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class KeyGenerationRequest
{
    public function __construct(
        private readonly KeySize $keySize,
        private readonly OutputFileNames $fileNames,
        private readonly bool $overwrite = false
    ) {
    }

    public function getKeySize(): KeySize
    {
        return $this->keySize;
    }

    public function getFileNames(): OutputFileNames
    {
        return $this->fileNames;
    }

    public function shouldOverwrite(): bool
    {
        return $this->overwrite;
    }
}
