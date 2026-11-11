#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use RobloxSigner\Signer;

$scriptPath = $argv[1] ?? __DIR__ . '/../script.lua';
$privateKeyPath = $argv[2] ?? __DIR__ . '/../keys/PrivateKey.pem';
$format = $argv[3] ?? 'v2019';

try {
    echo Signer::signFile($scriptPath, $privateKeyPath, $format);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . "\n");
    exit(1);
}
