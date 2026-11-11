<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\DerEncoder;
use RobloxSigner\Keys\Pkcs1PemEncoder;
use RobloxSigner\Keys\RsaCrtExponents;
use RobloxSigner\Keys\RsaCrtParameters;
use RobloxSigner\Keys\RsaPrimeFactors;
use RobloxSigner\Keys\RsaPrivateKey;
use RobloxSigner\Keys\RsaPublicKey;
use RobloxSigner\Tests\Support\TestKeys;

final class Pkcs1PemEncoderTest extends TestCase
{
    private Pkcs1PemEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new Pkcs1PemEncoder(new DerEncoder());
    }

    public function testPrivateKeyPemIsValidAndParseable(): void
    {
        $pem = TestKeys::privateKeyPem();

        self::assertStringStartsWith("-----BEGIN RSA PRIVATE KEY-----\n", $pem);
        self::assertStringEndsWith("-----END RSA PRIVATE KEY-----\n", $pem);
        self::assertStringNotContainsString("\r", $pem);
        $this->assertPemLinesAreWrapped($pem);

        $key = openssl_pkey_get_private($pem);
        self::assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertSame(2048, $details['bits']);
    }

    public function testPublicKeyPemIsValidAndParseable(): void
    {
        $pem = TestKeys::publicKeyPem();

        self::assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $pem);
        self::assertStringEndsWith("-----END PUBLIC KEY-----\n", $pem);
        self::assertStringNotContainsString("\r", $pem);
        $this->assertPemLinesAreWrapped($pem);

        $key = openssl_pkey_get_public($pem);
        self::assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertSame(2048, $details['bits']);
    }

    public function testReencodingOpenSslDetailsMatchesGeneratedPair(): void
    {
        $key = openssl_pkey_get_private(TestKeys::privateKeyPem());
        self::assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $rsa = $details['rsa'];

        $publicKey = new RsaPublicKey($rsa['n'], $rsa['e']);
        $privateKey = new RsaPrivateKey(
            $publicKey,
            $rsa['d'],
            new RsaCrtParameters(
                new RsaPrimeFactors($rsa['p'], $rsa['q']),
                new RsaCrtExponents($rsa['dmp1'], $rsa['dmq1']),
                $rsa['iqmp']
            )
        );

        self::assertSame(TestKeys::privateKeyPem(), $this->encoder->encodePrivateKey($privateKey));
        self::assertSame(TestKeys::publicKeyPem(), $this->encoder->encodePublicKey($publicKey));
    }

    private function assertPemLinesAreWrapped(string $pem): void
    {
        $lines = explode("\n", trim($pem));

        self::assertGreaterThan(2, count($lines));

        foreach (array_slice($lines, 1, -1) as $line) {
            self::assertLessThanOrEqual(64, strlen($line));
        }
    }
}
