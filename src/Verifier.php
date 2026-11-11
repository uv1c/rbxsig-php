<?php

declare(strict_types=1);

namespace RobloxSigner;

use InvalidArgumentException;
use RuntimeException;

/**
 * Verifies signed script output against a public key.
 */
final class Verifier
{
    /**
     * Verify a complete signed script (signature token followed by payload).
     *
     * @param string $signedScript Token plus script, as produced by Signer.
     * @param string $publicKeyPemOrPath Public key PEM string or PEM file path.
     */
    public static function verify(string $signedScript, string $publicKeyPemOrPath): bool
    {
        $token = self::extractToken($signedScript);
        $payload = self::extractPayload($signedScript);

        return self::verifyPayload($payload, $token, $publicKeyPemOrPath);
    }

    /**
     * Verify a signature token against a separately supplied payload.
     *
     * Use this for token-only / HTTP-header signatures.
     */
    public static function verifyPayload(
        string $payload,
        string $token,
        string $publicKeyPemOrPath
    ): bool {
        $publicKey = self::loadPublicKey($publicKeyPemOrPath);
        $signature = self::decodeToken($token);

        if ($signature === null) {
            return false;
        }

        $result = @openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA1);

        return $result === 1;
    }

    /**
     * Extract the leading signature token, e.g. --rbxsig2%...%.
     */
    public static function extractToken(string $signedScript): string
    {
        if (preg_match('/^(--rbxsig4|--rbxsig2|--rbxsig)?%[^%]*%/', $signedScript, $match) !== 1) {
            throw new InvalidArgumentException('Unable to find a Roblox signature token.');
        }

        return $match[0];
    }

    /**
     * Extract everything after the signature token.
     */
    public static function extractPayload(string $signedScript): string
    {
        $token = self::extractToken($signedScript);

        return substr($signedScript, strlen($token));
    }

    private static function decodeToken(string $token): ?string
    {
        if (preg_match('/%([^%]*)%$/', $token, $match) !== 1) {
            return null;
        }

        $decoded = base64_decode($match[1], true);

        return $decoded === false ? null : $decoded;
    }

    private static function loadPublicKey(string $publicKeyPemOrPath): \OpenSSLAsymmetricKey
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('The PHP openssl extension is required.');
        }

        $pem = $publicKeyPemOrPath;

        if (is_file($publicKeyPemOrPath)) {
            $contents = file_get_contents($publicKeyPemOrPath);

            if ($contents === false) {
                throw new RuntimeException(
                    "Unable to read public key from: {$publicKeyPemOrPath}"
                );
            }

            $pem = $contents;
        }

        $publicKey = @openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            throw new InvalidArgumentException('Invalid public key.');
        }

        return $publicKey;
    }
}
