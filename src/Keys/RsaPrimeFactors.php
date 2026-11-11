<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class RsaPrimeFactors
{
    public function __construct(
        private readonly string $primeP,
        private readonly string $primeQ
    ) {
    }

    public function getPrimeP(): string
    {
        return $this->primeP;
    }

    public function getPrimeQ(): string
    {
        return $this->primeQ;
    }
}
