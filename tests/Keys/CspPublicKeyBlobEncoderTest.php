<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\CspPublicKeyBlobEncoder;
use RobloxSigner\Keys\RsaPublicKey;
use RobloxSigner\Tests\Support\TestKeys;

final class CspPublicKeyBlobEncoderTest extends TestCase
{
    private const KNOWN_1024_HEADER = '0602000000a40000525341310004000001000100';

    private CspPublicKeyBlobEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new CspPublicKeyBlobEncoder();
    }

    public function testMatchesKnownGood1024BitHeader(): void
    {
        $modulus = str_repeat("\x80", 128);
        $blob = $this->encoder->encode(new RsaPublicKey($modulus, "\x01\x00\x01"));

        self::assertSame(148, strlen($blob));
        self::assertSame(self::KNOWN_1024_HEADER, bin2hex(substr($blob, 0, 20)));
        self::assertSame(strrev($modulus), substr($blob, 20));
    }

    public function testEncodesGenerated2048BitKey(): void
    {
        $keyPair = TestKeys::keyPair();
        $blob = $keyPair->getPublicKeyBlob();

        self::assertSame(276, strlen($blob));
        self::assertSame(
            '0602000000a40000525341310008000001000100',
            bin2hex(substr($blob, 0, 20))
        );
        self::assertSame(base64_encode($blob), $keyPair->getPublicKeyBlobBase64());
    }

    public function testEncodesSmallModulusAndExponent(): void
    {
        $blob = $this->encoder->encode(new RsaPublicKey("\x7f", "\x03"));

        self::assertSame(21, strlen($blob));
        self::assertSame('0602000000a4000052534131', bin2hex(substr($blob, 0, 12)));
        self::assertSame('07000000', bin2hex(substr($blob, 12, 4)));
        self::assertSame('03000000', bin2hex(substr($blob, 16, 4)));
        self::assertSame("\x7f", substr($blob, 20));
    }

    public function testLeadingZeroModulusBytesAreIgnored(): void
    {
        $blob = $this->encoder->encode(new RsaPublicKey("\x00\x80", "\x01\x00\x01"));

        self::assertSame(21, strlen($blob));
        self::assertSame('08000000', bin2hex(substr($blob, 12, 4)));
        self::assertSame("\x80", substr($blob, 20));
    }

    public function testZeroModulusThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('RSA modulus cannot be empty');

        $this->encoder->encode(new RsaPublicKey("\x00\x00", "\x01\x00\x01"));
    }

    public function testZeroExponentThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('RSA public exponent cannot be zero');

        $this->encoder->encode(new RsaPublicKey("\x80", "\x00"));
    }

    public function testTooLargeExponentThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('RSA public exponent must fit in 4 bytes');

        $this->encoder->encode(new RsaPublicKey("\x80", "\x01\x00\x00\x00\x01"));
    }
}
