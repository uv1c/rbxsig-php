<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\KeySize;

final class KeySizeTest extends TestCase
{
    public function testSupportedSizes(): void
    {
        self::assertSame(1024, KeySize::bits1024()->getBits());
        self::assertSame(2048, KeySize::bits2048()->getBits());
        self::assertSame(1024, KeySize::fromBits(1024)->getBits());
        self::assertSame(2048, KeySize::fromBits(2048)->getBits());
    }

    public function testUnsupportedSizeThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Only 1024 or 2048-bit keys are allowed');

        KeySize::fromBits(512);
    }

    public function testZeroSizeThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);

        KeySize::fromBits(0);
    }
}
