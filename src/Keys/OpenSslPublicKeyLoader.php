<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class OpenSslPublicKeyLoader
{
    private const RSA_PUBLIC_KEY_PATTERN = '/\A\s*-----BEGIN RSA PUBLIC KEY-----\s*(.*?)\s*-----END RSA PUBLIC KEY-----\s*\z/s';
    private const RSA_ENCRYPTION_OID = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    private const PEM_LINE_LENGTH = 64;

    public static function load(string $pem): \OpenSSLAsymmetricKey|false
    {
        return @openssl_pkey_get_public(self::toOpenSslPem($pem));
    }

    private static function toOpenSslPem(string $pem): string
    {
        if (preg_match(self::RSA_PUBLIC_KEY_PATTERN, $pem, $matches) !== 1) {
            return $pem;
        }

        $base64 = preg_replace('/\s+/', '', $matches[1]);
        $rsaPublicKey = base64_decode($base64 ?? '', true);

        if ($rsaPublicKey === false) {
            return $pem;
        }

        $derEncoder = new DerEncoder();
        $algorithmIdentifier = $derEncoder->encodeSequence(self::RSA_ENCRYPTION_OID . "\x05\x00");
        $subjectPublicKeyInfo = $derEncoder->encodeSequence(
            $algorithmIdentifier . $derEncoder->encodeBitString($rsaPublicKey)
        );
        $body = chunk_split(base64_encode($subjectPublicKeyInfo), self::PEM_LINE_LENGTH, "\n");

        return "-----BEGIN PUBLIC KEY-----\n"
            . $body
            . "-----END PUBLIC KEY-----\n";
    }
}