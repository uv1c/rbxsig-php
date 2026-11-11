<?php

declare(strict_types=1);

namespace RobloxSigner\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobloxSigner\SignatureFormat;
use RobloxSigner\Signer;
use RobloxSigner\SigningOptions;
use RobloxSigner\Tests\Support\Environment;
use RobloxSigner\Tests\Support\TestKeys;
use RobloxSigner\Verifier;

final class VerifierTest extends TestCase
{
    private const SCRIPT = "print('verify me')\n";

    #[DataProvider('formatProvider')]
    public function testVerifiesCompleteSignedScripts(SignatureFormat $format): void
    {
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem(), $format);

        self::assertTrue(Verifier::verify($signed, TestKeys::publicKeyPem()));
    }

    /** @return array<string, array{SignatureFormat}> */
    public static function formatProvider(): array
    {
        return [
            'classic' => [SignatureFormat::CLASSIC],
            'rbxsig' => [SignatureFormat::RBXSIG],
            'rbxsig2' => [SignatureFormat::RBXSIG2],
            'rbxsig4' => [SignatureFormat::RBXSIG4],
        ];
    }

    public function testTamperedPayloadFails(): void
    {
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem());

        self::assertFalse(Verifier::verify($signed . 'x', TestKeys::publicKeyPem()));
    }

    public function testTokenOnlySignatureVerifiesAgainstExplicitPayload(): void
    {
        $options = new SigningOptions(
            SignatureFormat::RBXSIG2,
            SigningOptions::LINE_ENDING_LF,
            '42',
            false
        );

        $token = Signer::signWithOptions(self::SCRIPT, TestKeys::privateKeyPem(), $options);

        self::assertTrue(Verifier::verifyPayload(
            "--rbxassetid%42%\n" . self::SCRIPT,
            $token,
            TestKeys::publicKeyPem()
        ));
        self::assertFalse(Verifier::verifyPayload(
            "--rbxassetid%43%\n" . self::SCRIPT,
            $token,
            TestKeys::publicKeyPem()
        ));
    }

    public function testExtractTokenAndPayload(): void
    {
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem(), SignatureFormat::RBXSIG4);
        $token = Verifier::extractToken($signed);

        self::assertStringStartsWith('--rbxsig4%', $token);
        self::assertStringEndsWith('%', $token);
        self::assertSame("\r\n" . self::SCRIPT, Verifier::extractPayload($signed));
    }

    public function testMissingTokenThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to find a Roblox signature token');

        Verifier::extractToken("print('unsigned')\n");
    }

    public function testInvalidBase64TokenFails(): void
    {
        self::assertFalse(Verifier::verify(
            '--rbxsig2%not-base64%' . "\r\n" . self::SCRIPT,
            TestKeys::publicKeyPem()
        ));
    }

    public function testVerifiesUsingPublicKeyFile(): void
    {
        $directory = Environment::createTempDirectory();
        $publicKeyPath = $directory . DIRECTORY_SEPARATOR . 'PublicKey.pem';
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem());

        try {
            file_put_contents($publicKeyPath, TestKeys::publicKeyPem());

            self::assertTrue(Verifier::verify($signed, $publicKeyPath));
        } finally {
            Environment::removeDirectory($directory);
        }
    }

    public function testInvalidPublicKeyThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid public key');

        Verifier::verify('--rbxsig2%AAAA%', 'not a public key');
    }
}
