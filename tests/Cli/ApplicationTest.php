<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Cli;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Cli\Application;
use RobloxSigner\Cli\CommandLineParser;
use RobloxSigner\Keys\KeyGenerationService;
use RobloxSigner\Tests\Support\Environment;

final class ApplicationTest extends TestCase
{
    public function testGlobalHelp(): void
    {
        [$exitCode, $stdout, $stderr] = $this->runApplication(['help']);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('rbxsign - Roblox key generation and script signing', $stdout);
        self::assertStringContainsString('keys:generate', $stdout);
        self::assertSame('', $stderr);
    }

    public function testNoCommandShowsHelp(): void
    {
        [$exitCode, $stdout] = $this->runApplication([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Usage:', $stdout);
    }

    public function testCommandHelpScreens(): void
    {
        [$keysExit, $keysOutput] = $this->runApplication(['keys:generate', '--help']);
        [$signExit, $signOutput] = $this->runApplication(['sign', '-h']);
        [$verifyExit, $verifyOutput] = $this->runApplication(['verify', '--help']);

        self::assertSame(0, $keysExit);
        self::assertStringContainsString('--out-dir', $keysOutput);
        self::assertSame(0, $signExit);
        self::assertStringContainsString('--token-only', $signOutput);
        self::assertSame(0, $verifyExit);
        self::assertStringContainsString('--payload', $verifyOutput);
    }

    public function testUnknownCommandFails(): void
    {
        [$exitCode, $stdout, $stderr] = $this->runApplication(['wat']);

        self::assertSame(1, $exitCode);
        self::assertSame('', $stdout);
        self::assertStringContainsString('Unknown command: wat', $stderr);
    }

    public function testSignRequiresKey(): void
    {
        [$exitCode, , $stderr] = $this->runApplication(['sign', '--script', 'script.lua']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('--key is required', $stderr);
    }

    public function testFormatAndEraAreMutuallyExclusive(): void
    {
        [$exitCode, , $stderr] = $this->runApplication([
            'sign',
            '--key', 'PrivateKey.pem',
            '--script', 'script.lua',
            '--format', 'rbxsig2',
            '--era', 'v2019',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Use either --format or --era', $stderr);
    }

    public function testInvalidLineEndingFails(): void
    {
        [$exitCode, , $stderr] = $this->runApplication([
            'sign',
            '--key', 'PrivateKey.pem',
            '--script', 'script.lua',
            '--line-ending', 'cr',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('--line-ending must be "crlf" or "lf"', $stderr);
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
}
