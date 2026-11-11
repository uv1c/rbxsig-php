<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class RsaCrtExponents
{
    public function __construct(
        private readonly string $exponentP,
        private readonly string $exponentQ
    ) {
    }

    public function getExponentP(): string
    {
        return $this->exponentP;
    }

    public function getExponentQ(): string
    {
        return $this->exponentQ;
    }
}
