<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\DerEncoder;

final class DerEncoderTest extends TestCase
{
    private DerEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new DerEncoder();
    }

    public function testEncodesSmallInteger(): void
    {
        self::assertSame("\x02\x01\x01", $this->encoder->encodeInteger("\x01"));
    }

    public function testEncodesZero(): void
    {
        self::assertSame("\x02\x01\x00", $this->encoder->encodeInteger("\x00"));
        self::assertSame("\x02\x01\x00", $this->encoder->encodeInteger("\x00\x00\x00"));
    }

    public function testStripsLeadingZeros(): void
    {
        self::assertSame("\x02\x01\x7f", $this->encoder->encodeInteger("\x00\x00\x7f"));
    }

    public function testAddsLeadingZeroWhenSignBitIsSet(): void
    {
        self::assertSame("\x02\x02\x00\x80", $this->encoder->encodeInteger("\x80"));
        self::assertSame("\x02\x02\x00\xff", $this->encoder->encodeInteger("\x00\xff"));
    }

    public function testUsesLongFormLengthForIntegers(): void
    {
        $value = "\x01" . str_repeat("\x00", 127);

        self::assertSame(
            "\x02\x81\x80" . $value,
            $this->encoder->encodeInteger($value)
        );
    }

    public function testEncodesSequence(): void
    {
        self::assertSame(
            "\x30\x03\x02\x01\x01",
            $this->encoder->encodeSequence("\x02\x01\x01")
        );
    }

    public function testEncodesLongSequenceLength(): void
    {
        $contents = str_repeat("\x01", 128);

        self::assertSame(
            "\x30\x81\x80" . $contents,
            $this->encoder->encodeSequence($contents)
        );
    }

    public function testEncodesTwoByteLongLength(): void
    {
        $contents = str_repeat("\x01", 256);

        self::assertSame(
            "\x30\x82\x01\x00" . $contents,
            $this->encoder->encodeSequence($contents)
        );
    }
}
