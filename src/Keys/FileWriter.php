<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

interface FileWriter
{
    public function write(string $path, string $contents, bool $overwrite = false): void;

    public function writeOwnerOnly(string $path, string $contents, bool $overwrite = false): void;
}
