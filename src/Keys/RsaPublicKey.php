<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

/** Both values are unsigned big-endian binary strings. */
final class RsaPublicKey
{
    public function __construct(
        private readonly string $modulus,
        private readonly string $publicExponent
    ) {
    }

    public function getModulus(): string
    {
        return $this->modulus;
    }

    public function getPublicExponent(): string
    {
        return $this->publicExponent;
    }
}
