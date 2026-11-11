<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\KeyGenerator;
use RobloxSigner\Keys\KeySize;
use RobloxSigner\Keys\OpenSslPublicKeyLoader;
use RobloxSigner\Tests\Support\Environment;

final class KeyGeneratorTest extends TestCase
{
    #[DataProvider('keySizeProvider')]
    public function testGeneratesConsistentKeyPairs(KeySize $keySize): void
    {
        $keyPair = KeyGenerator::create(Environment::opensslConfigPath())->generate($keySize);

        self::assertSame($keySize->getBits(), $keyPair->getBits());
        self::assertStringStartsWith("-----BEGIN RSA PRIVATE KEY-----\n", $keyPair->getPrivateKeyPem());
        self::assertStringStartsWith("-----BEGIN RSA PUBLIC KEY-----\n", $keyPair->getPublicKeyPem());
        self::assertSame(20 + intdiv($keySize->getBits(), 8), strlen($keyPair->getPublicKeyBlob()));

        $privateKey = openssl_pkey_get_private($keyPair->getPrivateKeyPem());
        $publicKey = OpenSslPublicKeyLoader::load($keyPair->getPublicKeyPem());

        self::assertNotFalse($privateKey);
        self::assertNotFalse($publicKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertIsArray($details);
        self::assertSame($keySize->getBits(), $details['bits']);

        $signature = '';
        self::assertTrue(openssl_sign('key-generation-test', $signature, $privateKey, OPENSSL_ALGO_SHA1));
        self::assertSame(
            1,
            openssl_verify('key-generation-test', $signature, $publicKey, OPENSSL_ALGO_SHA1)
        );
    }

    /** @return array<string, array{KeySize}> */
    public static function keySizeProvider(): array
    {
        return [
            '1024-bit' => [KeySize::bits1024()],
            '2048-bit' => [KeySize::bits2048()],
        ];
    }

    public function testCreateWithoutExplicitConfigGeneratesAKey(): void
    {
        if (Environment::opensslConfigPath() === null) {
            self::markTestSkipped('No OpenSSL configuration file is available.');
        }

        $keyPair = KeyGenerator::create()->generate(KeySize::bits1024());

        self::assertSame(1024, $keyPair->getBits());
        self::assertSame(148, strlen($keyPair->getPublicKeyBlob()));
    }

    public function testGenerated1024BitBlobMatchesKnownGoodHeader(): void
    {
        $keyPair = KeyGenerator::create(Environment::opensslConfigPath())
            ->generate(KeySize::bits1024());

        self::assertSame(148, strlen($keyPair->getPublicKeyBlob()));
        self::assertSame(
            '0602000000a40000525341310004000001000100',
            bin2hex(substr($keyPair->getPublicKeyBlob(), 0, 20))
        );
    }
}
