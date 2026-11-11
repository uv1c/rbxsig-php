<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use RuntimeException;

final class LocalFileWriter implements FileWriter
{
    private const OWNER_READ_WRITE = 0600;
    private const PUBLIC_READ = 0644;

    public function write(string $path, string $contents, bool $overwrite = false): void
    {
        $this->writeAtomically($path, $contents, self::PUBLIC_READ, $overwrite);
    }

    public function writeOwnerOnly(string $path, string $contents, bool $overwrite = false): void
    {
        $this->writeAtomically($path, $contents, self::OWNER_READ_WRITE, $overwrite);
    }

    private function writeAtomically(
        string $path,
        string $contents,
        int $mode,
        bool $overwrite
    ): void {
        $directory = dirname($path);
        $this->ensureDirectory($directory);

        if (!is_writable($directory)) {
            throw new RuntimeException("Directory is not writable: {$directory}");
        }

        if (!$overwrite && file_exists($path)) {
            throw new RuntimeException("Refusing to overwrite existing file: {$path}");
        }

        $temporaryPath = tempnam($directory, '.rbxsign-');

        if ($temporaryPath === false) {
            throw new RuntimeException("Cannot create a temporary file in {$directory}");
        }

        try {
            $written = file_put_contents($temporaryPath, $contents);

            if ($written === false || $written !== strlen($contents)) {
                throw new RuntimeException("Cannot write {$path}");
            }

            $this->restrictPermissions($temporaryPath, $mode);
            $this->replace($temporaryPath, $path, $overwrite);
        } catch (\Throwable $exception) {
            @unlink($temporaryPath);
            throw $exception;
        }
    }

    private function ensureDirectory(string $directory): void
    {
        if ($directory === '' || is_dir($directory)) {
            return;
        }

        if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException("Cannot create directory: {$directory}");
        }
    }

    private function restrictPermissions(string $path, int $mode): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            // chmod() does not change NTFS ACLs. The caller must protect the
            // directory with OS-level permissions instead.
            return;
        }

        if (chmod($path, $mode) === false) {
            throw new RuntimeException("Cannot set permissions on {$path}");
        }
    }

    private function replace(string $temporaryPath, string $path, bool $overwrite): void
    {
        if (PHP_OS_FAMILY === 'Windows' && file_exists($path)) {
            if (!$overwrite) {
                throw new RuntimeException("Refusing to overwrite existing file: {$path}");
            }

            if (!unlink($path)) {
                throw new RuntimeException("Cannot replace existing file: {$path}");
            }
        }

        if (!rename($temporaryPath, $path)) {
            throw new RuntimeException("Cannot move temporary file into place: {$path}");
        }
    }
}
