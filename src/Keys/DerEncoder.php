<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class DerEncoder
{
    private const TAG_INTEGER = "\x02";
    private const TAG_SEQUENCE = "\x30";
    private const SHORT_FORM_LENGTH_LIMIT = 0x80;
    private const LONG_FORM_LENGTH_FLAG = 0x80;
    private const SIGN_BIT = 0x80;

    /** @param string $unsignedBigEndian Unsigned big-endian integer bytes. */
    public function encodeInteger(string $unsignedBigEndian): string
    {
        $content = $this->withoutLeadingZeros($unsignedBigEndian);

        if (ord($content[0]) & self::SIGN_BIT) {
            $content = "\0" . $content;
        }

        return self::TAG_INTEGER . $this->encodeLength(strlen($content)) . $content;
    }

    public function encodeSequence(string $contents): string
    {
        return self::TAG_SEQUENCE . $this->encodeLength(strlen($contents)) . $contents;
    }

    private function withoutLeadingZeros(string $bytes): string
    {
        $trimmed = ltrim($bytes, "\0");

        return $trimmed === '' ? "\0" : $trimmed;
    }

    private function encodeLength(int $length): string
    {
        if ($length < self::SHORT_FORM_LENGTH_LIMIT) {
            return chr($length);
        }

        $lengthBytes = ltrim(pack('N', $length), "\0");

        return chr(self::LONG_FORM_LENGTH_FLAG | strlen($lengthBytes)) . $lengthBytes;
    }
}
