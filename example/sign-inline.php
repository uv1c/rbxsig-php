#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use function RobloxSigner\sign;

// In a web endpoint, this captures the inline Lua below as the response body.
ob_start();
?>
print("player joined the game")
-- Add join-script logic here.
<?php
$script = ob_get_clean();

try {
    header('Content-Type: text/plain; charset=utf-8');
    echo sign($script, 'pre2012');
} catch (Exception $exception) {
    error_log('Script signing failed: ' . $exception->getMessage());
    http_response_code(500);
    die('Internal Server Error');
}
