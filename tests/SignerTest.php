<?php

declare(strict_types=1);

namespace RobloxSigner\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Era;
use RobloxSigner\SignatureFormat;
use RobloxSigner\Signer;
use RobloxSigner\SigningOptions;
use RobloxSigner\Tests\Support\Environment;
use RobloxSigner\Tests\Support\TestKeys;
use RobloxSigner\Verifier;
use RuntimeException;

final class SignerTest extends TestCase
{
    private const SCRIPT = "print('hello from Roblox')\n";

    #[DataProvider('formatProvider')]
    public function testSignsWithEveryFormat(SignatureFormat $format): void
    {
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem(), $format);

        self::assertStringStartsWith($format->prefix() . '%', $signed);
        self::assertStringEndsWith('%' . "\r\n" . self::SCRIPT, $signed);
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

    public function testDefaultFormatIsRbxsig2(): void
    {
        $signed = Signer::signWithPem(self::SCRIPT, TestKeys::privateKeyPem());

        self::assertStringStartsWith('--rbxsig2%', $signed);
    }

    #[DataProvider('resolveFormatProvider')]
    public function testResolveFormat(Era|string|SignatureFormat $input, SignatureFormat $expected): void
    {
        self::assertSame($expected, Signer::resolveFormat($input));
    }

    /** @return array<string, array{Era|string|SignatureFormat, SignatureFormat}> */
    public static function resolveFormatProvider(): array
    {
        return [
            'format enum' => [SignatureFormat::RBXSIG4, SignatureFormat::RBXSIG4],
            'era enum' => [Era::V2018, SignatureFormat::RBXSIG2],
            'era string' => ['v2013', SignatureFormat::RBXSIG],
            'format string' => ['classic', SignatureFormat::CLASSIC],
            'uppercase format string' => ['RBXSIG4', SignatureFormat::RBXSIG4],
            'pre-2012 era string' => ['pre_2012', SignatureFormat::CLASSIC],
            'pre2012 alias' => ['pre2012', SignatureFormat::CLASSIC],
            'pre-2012 alias' => ['pre-2012', SignatureFormat::CLASSIC],
        ];
    }

    public function testUnknownFormatThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown era or signature format');

        Signer::resolveFormat('v1999');
    }

    public function testSignsScriptAndKeyFromFiles(): void
    {
        $directory = Environment::createTempDirectory();
        $scriptPath = $directory . DIRECTORY_SEPARATOR . 'script.lua';
        $keyPath = $directory . DIRECTORY_SEPARATOR . 'PrivateKey.pem';

        try {
            file_put_contents($scriptPath, self::SCRIPT);
            file_put_contents($keyPath, TestKeys::privateKeyPem());

            $fromStrings = Signer::sign(self::SCRIPT, $keyPath, SignatureFormat::RBXSIG2);
            $fromFiles = Signer::signFile($scriptPath, $keyPath, SignatureFormat::RBXSIG2);

            self::assertSame($fromStrings, $fromFiles);
            self::assertTrue(Verifier::verify($fromFiles, TestKeys::publicKeyPem()));
        } finally {
            Environment::removeDirectory($directory);
        }
    }

    public function testSignWithOptionsSupportsLfAndAssetId(): void
    {
        $options = new SigningOptions(
            SignatureFormat::RBXSIG4,
            SigningOptions::LINE_ENDING_LF,
            '123456'
        );

        $signed = Signer::signWithOptions(self::SCRIPT, TestKeys::privateKeyPem(), $options);
        $payload = "--rbxassetid%123456%\n" . self::SCRIPT;

        self::assertStringStartsWith('--rbxsig4%', $signed);
        self::assertStringEndsWith('%' . $payload, $signed);
        self::assertTrue(Verifier::verify($signed, TestKeys::publicKeyPem()));
    }

    public function testSignatureTokenContainsOnlyTheToken(): void
    {
        $options = new SigningOptions(
            SignatureFormat::RBXSIG2,
            SigningOptions::LINE_ENDING_CRLF,
            null,
            false
        );

        $token = Signer::signWithOptions(self::SCRIPT, TestKeys::privateKeyPem(), $options);

        self::assertMatchesRegularExpression('/^--rbxsig2%[A-Za-z0-9+\/=]+%$/', $token);
        self::assertStringNotContainsString(self::SCRIPT, $token);
        self::assertTrue(Verifier::verifyPayload(
            "\r\n" . self::SCRIPT,
            $token,
            TestKeys::publicKeyPem()
        ));
    }

    public function testMissingPrivateKeyFileThrows(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to read private key');

        Signer::sign(self::SCRIPT, __DIR__ . '/does-not-exist.pem');
    }

    public function testInvalidPrivateKeyThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid private key');

        Signer::signWithPem(self::SCRIPT, 'not a private key');
    }

    public function testInvalidLineEndingThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Line ending must be');

        new SigningOptions(SignatureFormat::RBXSIG2, "\n\r");
    }

    public function testInvalidAssetIdThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Asset ID must contain digits only');

        new SigningOptions(SignatureFormat::RBXSIG2, SigningOptions::LINE_ENDING_CRLF, '123abc');
    }

    public function testDefaultSigningOptionsMatchSignerDefault(): void
    {
        $signed = Signer::signWithOptions(
            self::SCRIPT,
            TestKeys::privateKeyPem(),
            new SigningOptions()
        );

        self::assertStringStartsWith('--rbxsig2%', $signed);
    }

}
