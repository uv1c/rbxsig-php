<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Cli\Application;
use RobloxSigner\Cli\CommandLineParser;
use RobloxSigner\Keys\KeyGenerationService;
use RobloxSigner\Keys\OpenSslPublicKeyLoader;
use RobloxSigner\Tests\Support\Environment;

final class PipelineTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = Environment::createTempDirectory('rbxsig-pipeline-');
    }

    protected function tearDown(): void
    {
        Environment::removeDirectory($this->directory);
    }

    public function testGenerateSignAndVerifyPipeline(): void
    {
        $privateKeyPath = $this->path('PrivateKey.pem');
        $publicKeyPath = $this->path('PublicKey.pem');
        $blobPath = $this->path('PublicKeyBlob.txt');

        [$exitCode, $stdout, $stderr] = $this->runApplication([
            'keys:generate',
            '--bits', '1024',
            '--out-dir', $this->directory,
        ]);

        self::assertSame(0, $exitCode, $stderr);
        self::assertStringContainsString('Generated 1024-bit key pair', $stdout);
        self::assertFileExists($privateKeyPath);
        self::assertFileExists($publicKeyPath);
        self::assertFileExists($blobPath);
        self::assertFileDoesNotExist($this->path('PrivateKey_1024.pem'));

        $privateKeyPem = (string) file_get_contents($privateKeyPath);
        $publicKeyPem = (string) file_get_contents($publicKeyPath);
        $blob = base64_decode(trim((string) file_get_contents($blobPath)), true);

        self::assertIsString($blob);
        self::assertSame(148, strlen($blob));
        self::assertSame(
            '0602000000a40000525341310004000001000100',
            bin2hex(substr($blob, 0, 20))
        );

        $privateDetails = openssl_pkey_get_details(openssl_pkey_get_private($privateKeyPem));
        $publicDetails = openssl_pkey_get_details(OpenSslPublicKeyLoader::load($publicKeyPem));
        self::assertIsArray($privateDetails);
        self::assertIsArray($publicDetails);
        self::assertSame(1024, $privateDetails['bits']);
        self::assertSame(1024, $publicDetails['bits']);

        [$secondExit, , $secondError] = $this->runApplication([
            'keys:generate',
            '--bits', '1024',
            '--out-dir', $this->directory,
        ]);

        self::assertSame(1, $secondExit);
        self::assertStringContainsString('Refusing to overwrite existing file', $secondError);
        self::assertSame($privateKeyPem, file_get_contents($privateKeyPath));

        [$forceExit, , $forceError] = $this->runApplication([
            'keys:generate',
            '--bits', '1024',
            '--out-dir', $this->directory,
            '--force',
        ]);

        self::assertSame(0, $forceExit, $forceError);
        self::assertNotSame($privateKeyPem, file_get_contents($privateKeyPath));

        $scriptPath = $this->path('script.lua');
        $signedPath = $this->path('signed.lua');
        $script = "print('pipeline')\n";
        file_put_contents($scriptPath, $script);

        [$signExit, , $signError] = $this->runApplication([
            'sign',
            '--key', $privateKeyPath,
            '--script', $scriptPath,
            '--format', 'rbxsig4',
            '--line-ending', 'lf',
            '--out', $signedPath,
        ]);

        self::assertSame(0, $signExit, $signError);
        $signed = (string) file_get_contents($signedPath);
        self::assertStringStartsWith('--rbxsig4%', $signed);
        self::assertStringEndsWith('%' . "\n" . $script, $signed);

        [$verifyExit, $verifyOutput, $verifyError] = $this->runApplication([
            'verify',
            '--signed', $signedPath,
            '--public-key', $publicKeyPath,
        ]);

        self::assertSame(0, $verifyExit, $verifyError);
        self::assertStringContainsString('Signature is valid', $verifyOutput);

        file_put_contents($signedPath, 'x', FILE_APPEND);
        [$tamperedExit, $tamperedOutput] = $this->runApplication([
            'verify',
            '--signed', $signedPath,
            '--public-key', $publicKeyPath,
        ]);

        self::assertSame(1, $tamperedExit);
        self::assertStringContainsString('Signature is invalid', $tamperedOutput);
    }

    public function testTokenOnlyCliSignatureVerifiesWithPayloadFile(): void
    {
        [$generateExit, , $generateError] = $this->runApplication([
            'keys:generate',
            '--bits', '1024',
            '--out-dir', $this->directory,
        ]);
        self::assertSame(0, $generateExit, $generateError);

        $script = "print('token only')\n";
        $scriptPath = $this->path('script.lua');
        $tokenPath = $this->path('token.txt');
        $payloadPath = $this->path('payload.txt');
        file_put_contents($scriptPath, $script);
        file_put_contents($payloadPath, "\r\n" . $script);

        [$signExit, , $signError] = $this->runApplication([
            'sign',
            '--key', $this->path('PrivateKey.pem'),
            '--script', $scriptPath,
            '--format', 'rbxsig2',
            '--token-only',
            '--out', $tokenPath,
        ]);

        self::assertSame(0, $signExit, $signError);

        $token = (string) file_get_contents($tokenPath);
        self::assertMatchesRegularExpression('/^--rbxsig2%[A-Za-z0-9+\/=]+%$/', $token);

        [$verifyExit, $verifyOutput, $verifyError] = $this->runApplication([
            'verify',
            '--signed', $tokenPath,
            '--payload', $payloadPath,
            '--public-key', $this->path('PublicKey.pem'),
        ]);

        self::assertSame(0, $verifyExit, $verifyError);
        self::assertStringContainsString('Signature is valid', $verifyOutput);
    }

    /** @param string[] $arguments */
    private function runApplication(array $arguments): array
    {
        $stdout = fopen('php://temp', 'w+');
        $stderr = fopen('php://temp', 'w+');

        if ($stdout === false || $stderr === false) {
            self::fail('Cannot open temporary streams.');
        }

        $application = new Application(
            KeyGenerationService::create(Environment::opensslConfigPath()),
            new CommandLineParser(),
            $stdout,
            $stderr
        );

        $exitCode = $application->run($arguments);
        rewind($stdout);
        rewind($stderr);

        $stdoutContents = stream_get_contents($stdout);
        $stderrContents = stream_get_contents($stderr);

        fclose($stdout);
        fclose($stderr);

        return [$exitCode, (string) $stdoutContents, (string) $stderrContents];
    }

    private function path(string $name): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . $name;
    }
}
