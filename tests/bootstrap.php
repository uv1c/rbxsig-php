<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use RobloxSigner\Tests\Support\Environment;

// PHP on Windows often cannot locate openssl.cnf on its own. Point OpenSSL at
// the copy shipped with the PHP build when the variable is not already set.
$opensslConfig = Environment::opensslConfigPath();

if ($opensslConfig !== null && (getenv('OPENSSL_CONF') === false || getenv('OPENSSL_CONF') === '')) {
    putenv('OPENSSL_CONF=' . $opensslConfig);
}
