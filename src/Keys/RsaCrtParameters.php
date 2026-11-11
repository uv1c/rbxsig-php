<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class RsaCrtParameters
{
    public function __construct(
        private readonly RsaPrimeFactors $primeFactors,
        private readonly RsaCrtExponents $exponents,
        private readonly string $coefficient
    ) {
    }

    public function getPrimeFactors(): RsaPrimeFactors
    {
        return $this->primeFactors;
    }

    public function getExponents(): RsaCrtExponents
    {
        return $this->exponents;
    }

    public function getCoefficient(): string
    {
        return $this->coefficient;
    }
}
