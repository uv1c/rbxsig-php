<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class KeyGenerationService
{
    public function __construct(
        private readonly KeyGenerator $keyGenerator,
        private readonly KeyFileExporter $keyFileExporter
    ) {
    }

    public static function create(?string $opensslConfigPath = null): self
    {
        return new self(
            KeyGenerator::create($opensslConfigPath),
            new KeyFileExporter(new LocalFileWriter())
        );
    }

    public function generate(KeyGenerationRequest $request): KeyPair
    {
        $keyPair = $this->keyGenerator->generate($request->getKeySize());

        $this->keyFileExporter->exportKeyPair(
            $keyPair,
            $request->getFileNames(),
            $request->shouldOverwrite()
        );

        return $keyPair;
    }
}
