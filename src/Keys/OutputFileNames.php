<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class OutputFileNames
{
    public const DEFAULT_PRIVATE_KEY = 'PrivateKey.pem';
    public const DEFAULT_PUBLIC_KEY = 'PublicKey.pem';
    public const DEFAULT_PUBLIC_KEY_BLOB = 'PublicKeyBlob.txt';

    public function __construct(
        private readonly string $privateKey = self::DEFAULT_PRIVATE_KEY,
        private readonly string $publicKey = self::DEFAULT_PUBLIC_KEY,
        private readonly string $publicKeyBlob = self::DEFAULT_PUBLIC_KEY_BLOB
    ) {
    }

    /**
     * Build the default exact filenames inside a directory.
     */
    public static function fromDirectory(string $directory): self
    {
        $normalized = rtrim($directory, '/\\');

        if ($normalized === '' && $directory !== '') {
            // A bare root such as "/" or "\".
            $normalized = $directory[0];
        } elseif (preg_match('/^[A-Za-z]:$/', $normalized) === 1 && $directory !== $normalized) {
            // A Windows drive root such as "C:\" or "C:/".
            $normalized .= DIRECTORY_SEPARATOR;
        }

        $prefix = $normalized === ''
            ? ''
            : (str_ends_with($normalized, '/') || str_ends_with($normalized, '\\')
                ? $normalized
                : $normalized . DIRECTORY_SEPARATOR);

        return new self(
            $prefix . self::DEFAULT_PRIVATE_KEY,
            $prefix . self::DEFAULT_PUBLIC_KEY,
            $prefix . self::DEFAULT_PUBLIC_KEY_BLOB
        );
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getPublicKeyBlob(): string
    {
        return $this->publicKeyBlob;
    }
}
