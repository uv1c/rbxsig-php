<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Support;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class Environment
{
    /**
     * Locate an OpenSSL configuration file usable by openssl_pkey_new().
     */
    public static function opensslConfigPath(): ?string
    {
        $configured = getenv('OPENSSL_CONF');

        if (is_string($configured) && $configured !== '' && is_file($configured)) {
            return $configured;
        }

        $candidates = [
            dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'extras'
                . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf',
            '/etc/ssl/openssl.cnf',
            '/usr/local/etc/openssl/openssl.cnf',
            '/usr/local/ssl/openssl.cnf',
            '/usr/lib/ssl/openssl.cnf',
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    public static function createTempDirectory(string $prefix = 'rbxsig-test-'): string
    {
        $directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $prefix . bin2hex(random_bytes(8));

        if (!mkdir($directory, 0700) && !is_dir($directory)) {
            throw new \RuntimeException("Cannot create temporary directory: {$directory}");
        }

        return $directory;
    }

    public static function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($directory);
    }
}
