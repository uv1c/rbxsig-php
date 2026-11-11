#!/usr/bin/env php
<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "rbxsign is a CLI tool and must not be exposed over HTTP.\n");
    exit(1);
}

$autoloadPath = $GLOBALS['_composer_autoload_path'] ?? __DIR__ . '/../vendor/autoload.php';

if (!is_file($autoloadPath)) {
    fwrite(STDERR, "Run composer install first.\n");
    exit(1);
}

require $autoloadPath;

use RobloxSigner\Cli\Application;
use RobloxSigner\Cli\CommandLineParser;
use RobloxSigner\Keys\KeyGenerationService;

$application = new Application(
    KeyGenerationService::create(),
    new CommandLineParser()
);

exit($application->run(array_slice($argv, 1)));
