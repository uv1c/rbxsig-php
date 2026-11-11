<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use InvalidArgumentException;

/**
 * Encodes a Windows CryptoAPI PUBLICKEYBLOB:
 * BLOBHEADER, then RSAPUBKEY ("RSA1", bit length, exponent), then the
 * little-endian modulus.
 *
 * The algorithm ID is CALG_RSA_KEYX (0x0000A400), matching the known-good
 * Roblox public key blobs. Windows accepts CALG_RSA_SIGN in some import paths,
 * but matching the reference format is safer.
 */
final class CspPublicKeyBlobEncoder
{
    private const BLOB_TYPE_PUBLIC_KEY = 0x06;
    private const BLOB_VERSION = 0x02;
    private const BLOB_RESERVED = 0x0000;
    private const ALGORITHM_ID_RSA_KEYX = 0x0000A400;
    private const RSA_PUBLIC_KEY_MAGIC = 'RSA1';
    private const BITS_PER_BYTE = 8;
    private const EXPONENT_FIELD_BYTES = 4;

    public function encode(RsaPublicKey $publicKey): string
    {
        $modulus = ltrim($publicKey->getModulus(), "\0");

        if ($modulus === '') {
            throw new InvalidArgumentException('RSA modulus cannot be empty.');
        }

        $bitLength = $this->bitLength($modulus);
        $modulusLength = intdiv($bitLength + self::BITS_PER_BYTE - 1, self::BITS_PER_BYTE);

        // The CSP blob always stores bitlen/8 modulus bytes, even when the
        // most significant byte happens to be zero.
        $modulus = str_pad($modulus, $modulusLength, "\0", STR_PAD_LEFT);

        return $this->encodeBlobHeader()
            . self::RSA_PUBLIC_KEY_MAGIC
            . pack('V', $bitLength)
            . $this->encodeExponentField($publicKey->getPublicExponent())
            . strrev($modulus);
    }

    private function encodeBlobHeader(): string
    {
        return pack(
            'CCvV',
            self::BLOB_TYPE_PUBLIC_KEY,
            self::BLOB_VERSION,
            self::BLOB_RESERVED,
            self::ALGORITHM_ID_RSA_KEYX
        );
    }

    private function encodeExponentField(string $bigEndianExponent): string
    {
        $exponent = ltrim($bigEndianExponent, "\0");

        if ($exponent === '') {
            throw new InvalidArgumentException('RSA public exponent cannot be zero.');
        }

        if (strlen($exponent) > self::EXPONENT_FIELD_BYTES) {
            throw new InvalidArgumentException('RSA public exponent must fit in 4 bytes.');
        }

        return str_pad(strrev($exponent), self::EXPONENT_FIELD_BYTES, "\0");
    }

    private function bitLength(string $bigEndianBytes): int
    {
        $firstByte = ord($bigEndianBytes[0]);
        $firstByteBits = 0;

        while ($firstByte > 0) {
            $firstByteBits++;
            $firstByte >>= 1;
        }

        return (strlen($bigEndianBytes) - 1) * self::BITS_PER_BYTE + $firstByteBits;
    }
}
