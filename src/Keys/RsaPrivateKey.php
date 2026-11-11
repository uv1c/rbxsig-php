<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class RsaPrivateKey
{
    public function __construct(
        private readonly RsaPublicKey $publicKey,
        private readonly string $privateExponent,
        private readonly RsaCrtParameters $crtParameters
    ) {
    }

    public function getPublicKey(): RsaPublicKey
    {
        return $this->publicKey;
    }

    public function getPrivateExponent(): string
    {
        return $this->privateExponent;
    }

    public function getCrtParameters(): RsaCrtParameters
    {
        return $this->crtParameters;
    }
}
