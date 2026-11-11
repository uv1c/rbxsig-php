<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

/**
 * Immutable in-memory key pair: PEM files plus the raw CSP public key blob.
 */
final class KeyPair
{
    public function __construct(
        private readonly KeySize $keySize,
        private readonly string $privateKeyPem,
        private readonly string $publicKeyPem,
        private readonly string $publicKeyBlob
    ) {
    }

    public function getBits(): int
    {
        return $this->keySize->getBits();
    }

    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    public function getPublicKeyPem(): string
    {
        return $this->publicKeyPem;
    }

    /**
     * Raw CSP PUBLICKEYBLOB bytes (not base64).
     */
    public function getPublicKeyBlob(): string
    {
        return $this->publicKeyBlob;
    }

    public function getPublicKeyBlobBase64(): string
    {
        return base64_encode($this->publicKeyBlob);
    }
}
