<?php

declare(strict_types=1);

namespace RobloxSigner;

use InvalidArgumentException;
use RuntimeException;

/**
 * Signs Roblox Lua scripts using RSA/SHA-1.
 *
 * The signature covers the exact payload sent after the signature token:
 * an optional --rbxassetid%...% line, the line ending, and the script bytes.
 * Do not normalize line endings after signing.
 */
class Signer
{
    /**
     * Sign a Lua script using a private key file.
     *
     * @param string $scriptContent Raw Lua script content (without leading newline).
     * @param string $privateKeyPath Path to PrivateKey.pem.
     * @param Era|string|SignatureFormat $era Era, era name, or explicit format.
     * @return string Signed script output ready to send to the client.
     */
    public static function sign(
        string $scriptContent,
        string $privateKeyPath,
        Era|string|SignatureFormat $era = Era::V2019
    ): string {
        $privateKeyPem = self::readFile($privateKeyPath, 'private key');

        return self::signWithOptions(
            $scriptContent,
            $privateKeyPem,
            new SigningOptions(self::resolveFormat($era))
        );
    }

    /**
     * Sign a Lua script using a PEM string or private key object.
     *
     * @param string $privateKeyPem PEM-encoded private key.
     */
    public static function signWithPem(
        string $scriptContent,
        string $privateKeyPem,
        Era|string|SignatureFormat $era = Era::V2019
    ): string {
        return self::signWithOptions(
            $scriptContent,
            $privateKeyPem,
            new SigningOptions(self::resolveFormat($era))
        );
    }

    /**
     * Read and sign a script file.
     */
    public static function signFile(
        string $scriptPath,
        string $privateKeyPath,
        Era|string|SignatureFormat $era = Era::V2019
    ): string {
        $scriptContent = self::readFile($scriptPath, 'script');
        $privateKeyPem = self::readFile($privateKeyPath, 'private key');

        return self::signWithOptions(
            $scriptContent,
            $privateKeyPem,
            new SigningOptions(self::resolveFormat($era))
        );
    }

    /**
     * Sign with full control over the wrapper, line ending, and asset ID.
     */
    public static function signWithOptions(
        string $scriptContent,
        string $privateKeyPem,
        SigningOptions $options
    ): string {
        self::requireOpenSsl();

        $privateKey = self::loadPrivateKey($privateKeyPem);
        $payload = self::buildPayload($scriptContent, $options);

        $signature = '';
        $ok = @openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA1);

        if ($ok !== true) {
            throw new RuntimeException('openssl_sign failed: ' . self::lastOpenSslError());
        }

        $token = $options->getFormat()->prefix()
            . '%'
            . base64_encode($signature)
            . '%';

        return $options->includesScript() ? $token . $payload : $token;
    }

    /**
     * Convert an era name, explicit format name, or enum into a format.
     */
    public static function resolveFormat(Era|string|SignatureFormat $format): SignatureFormat
    {
        if ($format instanceof SignatureFormat) {
            return $format;
        }

        if ($format instanceof Era) {
            return $format->signatureFormat();
        }

        $normalizedFormat = strtolower(trim($format));
        $normalizedFormat = str_replace('-', '_', $normalizedFormat);

        if ($normalizedFormat === 'pre2012') {
            $normalizedFormat = 'pre_2012';
        }

        $era = Era::tryFrom($normalizedFormat);
        if ($era !== null) {
            return $era->signatureFormat();
        }

        $signatureFormat = SignatureFormat::tryFrom($normalizedFormat);
        if ($signatureFormat !== null) {
            return $signatureFormat;
        }

        throw new InvalidArgumentException(sprintf(
            'Unknown era or signature format "%s". Allowed eras: %s. Allowed formats: %s.',
            $format,
            implode(', ', array_column(Era::cases(), 'value')),
            implode(', ', array_column(SignatureFormat::cases(), 'value'))
        ));
    }

    private static function buildPayload(string $scriptContent, SigningOptions $options): string
    {
        $assetLine = '';

        if ($options->getAssetId() !== null) {
            $assetLine = '--rbxassetid%' . $options->getAssetId() . '%';
        }

        return $assetLine . $options->getLineEnding() . $scriptContent;
    }

    private static function loadPrivateKey(string $pem): \OpenSSLAsymmetricKey
    {
        $privateKey = @openssl_pkey_get_private($pem);

        if ($privateKey === false) {
            throw new InvalidArgumentException(
                'Invalid private key: ' . self::lastOpenSslError()
            );
        }

        return $privateKey;
    }

    private static function readFile(string $path, string $label): string
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException("Unable to read {$label} from: {$path}");
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new RuntimeException("Unable to read {$label} from: {$path}");
        }

        return $contents;
    }

    private static function requireOpenSsl(): void
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('The PHP openssl extension is required.');
        }
    }

    private static function lastOpenSslError(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return $errors === [] ? 'unknown OpenSSL error' : implode('; ', $errors);
    }
}
