<?php

declare(strict_types=1);

namespace RobloxSigner\Tests;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Tests\Support\Environment;
use RobloxSigner\Tests\Support\TestKeys;
use RobloxSigner\Verifier;
use RuntimeException;

use function RobloxSigner\sign;

final class QuickSignTest extends TestCase
{
    private const SCRIPT = "print('inline')\n";

    public function testSignsInlineScriptWithExplicitKeyPath(): void
    {
        $directory = Environment::createTempDirectory();
        $keyPath = $directory . DIRECTORY_SEPARATOR . 'PrivateKey.pem';

        try {
            file_put_contents($keyPath, TestKeys::privateKeyPem());

            $signed = sign(self::SCRIPT, 'pre2012', $keyPath);

            self::assertStringStartsWith('%', $signed);
            self::assertStringEndsWith('%' . "\r\n" . self::SCRIPT, $signed);
            self::assertTrue(Verifier::verify($signed, TestKeys::publicKeyPem()));
        } finally {
            Environment::removeDirectory($directory);
        }
    }

    public function testUsesEnvironmentKeyPath(): void
    {
        $directory = Environment::createTempDirectory();
        $keyPath = $directory . DIRECTORY_SEPARATOR . 'PrivateKey.pem';
        $previousEnvironment = getenv('RBXSIG_PRIVATE_KEY');

        try {
            file_put_contents($keyPath, TestKeys::privateKeyPem());
            putenv('RBXSIG_PRIVATE_KEY=' . $keyPath);

            $signed = sign(self::SCRIPT, 'rbxsig2');

            self::assertStringStartsWith('--rbxsig2%', $signed);
            self::assertTrue(Verifier::verify($signed, TestKeys::publicKeyPem()));
        } finally {
            $this->restoreEnvironment($previousEnvironment);
            Environment::removeDirectory($directory);
        }
    }

    public function testFindsConventionalKeyRelativeToWorkingDirectory(): void
    {
        $directory = Environment::createTempDirectory();
        $keyDirectory = $directory . DIRECTORY_SEPARATOR . 'keys';
        $previousWorkingDirectory = getcwd();
        $previousEnvironment = getenv('RBXSIG_PRIVATE_KEY');

        mkdir($keyDirectory, 0777, true);
        file_put_contents(
            $keyDirectory . DIRECTORY_SEPARATOR . 'PrivateKey.pem',
            TestKeys::privateKeyPem()
        );

        try {
            putenv('RBXSIG_PRIVATE_KEY=');
            chdir($directory);

            $signed = sign(self::SCRIPT, 'rbxsig4');

            self::assertStringStartsWith('--rbxsig4%', $signed);
            self::assertTrue(Verifier::verify($signed, TestKeys::publicKeyPem()));
        } finally {
            if ($previousWorkingDirectory !== false) {
                chdir($previousWorkingDirectory);
            }

            $this->restoreEnvironment($previousEnvironment);
            Environment::removeDirectory($directory);
        }
    }

    public function testReportsMissingKey(): void
    {
        $directory = Environment::createTempDirectory();
        $previousWorkingDirectory = getcwd();
        $previousEnvironment = getenv('RBXSIG_PRIVATE_KEY');

        try {
            putenv('RBXSIG_PRIVATE_KEY=');
            chdir($directory);

            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage('No private key found');

            sign(self::SCRIPT, 'rbxsig2');
        } finally {
            if ($previousWorkingDirectory !== false) {
                chdir($previousWorkingDirectory);
            }

            $this->restoreEnvironment($previousEnvironment);
            Environment::removeDirectory($directory);
        }
    }

    private function restoreEnvironment(string|false $previous): void
    {
        putenv($previous === false ? 'RBXSIG_PRIVATE_KEY=' : 'RBXSIG_PRIVATE_KEY=' . $previous);
    }
}
