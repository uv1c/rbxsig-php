<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use InvalidArgumentException;

final class KeySize
{
    public const BITS_1024 = 1024;
    public const BITS_2048 = 2048;

    private const SUPPORTED_BITS = [self::BITS_1024, self::BITS_2048];

    private function __construct(private readonly int $bits)
    {
    }

    public static function fromBits(int $bits): self
    {
        if (self::isSupported($bits)) {
            return new self($bits);
        }

        throw new InvalidArgumentException(
            sprintf('Only %s-bit keys are allowed.', implode(' or ', self::SUPPORTED_BITS))
        );
    }

    public static function bits1024(): self
    {
        return new self(self::BITS_1024);
    }

    public static function bits2048(): self
    {
        return new self(self::BITS_2048);
    }

    public function getBits(): int
    {
        return $this->bits;
    }

    private static function isSupported(int $bits): bool
    {
        return in_array($bits, self::SUPPORTED_BITS, true);
    }
}
