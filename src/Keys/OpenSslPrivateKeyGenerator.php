<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use RuntimeException;

final class OpenSslPrivateKeyGenerator implements PrivateKeyGenerator
{
    public function __construct(private readonly ?string $opensslConfigPath = null)
    {
    }

    public function generate(KeySize $keySize): RsaPrivateKey
    {
        if (extension_loaded('openssl') === false) {
            throw new RuntimeException('The PHP openssl extension is required.');
        }

        $options = [
            'private_key_bits' => $keySize->getBits(),
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $configPath = $this->resolveConfigPath();

        if ($configPath !== null) {
            $options['config'] = $configPath;
        }

        $keyResource = @openssl_pkey_new($options);

        if ($keyResource === false) {
            throw new RuntimeException($this->generationError());
        }

        $keyDetails = @openssl_pkey_get_details($keyResource);

        if ($keyDetails === false) {
            throw new RuntimeException('Cannot read generated key: ' . $this->errors());
        }

        return $this->buildPrivateKey($keyDetails['rsa']);
    }

    /** @param array<string, string> $opensslRsaParts */
    private function buildPrivateKey(array $opensslRsaParts): RsaPrivateKey
    {
        $publicKey = new RsaPublicKey($opensslRsaParts['n'], $opensslRsaParts['e']);

        $crtParameters = new RsaCrtParameters(
            new RsaPrimeFactors($opensslRsaParts['p'], $opensslRsaParts['q']),
            new RsaCrtExponents($opensslRsaParts['dmp1'], $opensslRsaParts['dmq1']),
            $opensslRsaParts['iqmp']
        );

        return new RsaPrivateKey($publicKey, $opensslRsaParts['d'], $crtParameters);
    }

    private function generationError(): string
    {
        $errors = $this->errors();
        $message = 'Key generation failed: ' . $errors;

        if (stripos($errors, 'configuration file') !== false
            || stripos($errors, 'no such file') !== false) {
            $message .= ' On Windows, set OPENSSL_CONF to your PHP extras/ssl/openssl.cnf '
                . 'or pass the config path to OpenSslPrivateKeyGenerator.';
        }

        return $message;
    }

    /**
     * Use the caller's explicit path when given. On Windows, fall back to the
     * openssl.cnf shipped with the PHP build, which PHP does not always find
     * on its own.
     */
    private function resolveConfigPath(): ?string
    {
        if ($this->opensslConfigPath !== null) {
            return $this->opensslConfigPath;
        }

        if (PHP_OS_FAMILY !== 'Windows') {
            return null;
        }

        $candidate = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras'
            . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';

        return is_file($candidate) ? $candidate : null;
    }

    private function errors(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return $errors === [] ? 'unknown OpenSSL error' : implode('; ', $errors);
    }
}
