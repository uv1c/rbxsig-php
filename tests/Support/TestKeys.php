<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Support;

use RobloxSigner\Keys\KeyGenerator;
use RobloxSigner\Keys\KeyPair;
use RobloxSigner\Keys\KeySize;

/**
 * Lazily generated, throw-away key pair shared by tests in this process.
 *
 * Using a runtime key avoids committing private key material to the repo while
 * keeping the test suite fast.
 */
final class TestKeys
{
    private static ?KeyPair $keyPair = null;

    public static function keyPair(): KeyPair
    {
        return self::$keyPair ??= KeyGenerator::create(Environment::opensslConfigPath())
            ->generate(KeySize::bits2048());
    }

    public static function privateKeyPem(): string
    {
        return self::keyPair()->getPrivateKeyPem();
    }

    public static function publicKeyPem(): string
    {
        return self::keyPair()->getPublicKeyPem();
    }
}
