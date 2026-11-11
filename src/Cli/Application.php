<?php

declare(strict_types=1);

namespace RobloxSigner\Cli;

use InvalidArgumentException;
use RobloxSigner\Era;
use RobloxSigner\Keys\KeyGenerationService;
use RobloxSigner\Signer;
use RobloxSigner\SigningOptions;
use RobloxSigner\Verifier;

final class Application
{
    private const EXIT_SUCCESS = 0;
    private const EXIT_FAILURE = 1;

    /** @var resource */
    private $stdout;

    /** @var resource */
    private $stderr;

    public function __construct(
        private readonly KeyGenerationService $keyGenerationService,
        private readonly CommandLineParser $commandLineParser,
        $stdout = null,
        $stderr = null
    ) {
        $this->stdout = $stdout ?? STDOUT;
        $this->stderr = $stderr ?? STDERR;
    }

    /** @param string[] $arguments */
    public function run(array $arguments): int
    {
        $command = array_shift($arguments) ?? 'help';

        try {
            return match ($command) {
                'keys:generate' => $this->generateKeys($arguments),
                'sign' => $this->sign($arguments),
                'verify' => $this->verify($arguments),
                'help', '--help', '-h' => $this->printHelp(),
                default => throw new InvalidArgumentException("Unknown command: {$command}"),
            };
        } catch (\Throwable $exception) {
            fwrite($this->stderr, $exception->getMessage() . "\n");

            return self::EXIT_FAILURE;
        }
    }

    /** @param string[] $arguments */
    private function generateKeys(array $arguments): int
    {
        if ($this->isHelpRequested($arguments)) {
            fwrite($this->stdout, $this->keyGenerationUsage());

            return self::EXIT_SUCCESS;
        }

        $request = $this->commandLineParser->parse($arguments);
        $keyPair = $this->keyGenerationService->generate($request);

        fwrite($this->stdout, sprintf(
            "Generated %d-bit key pair:\n"
            . "  Private key: %s\n"
            . "  Public key:  %s\n"
            . "  Public blob: %s\n",
            $keyPair->getBits(),
            $request->getFileNames()->getPrivateKey(),
            $request->getFileNames()->getPublicKey(),
            $request->getFileNames()->getPublicKeyBlob()
        ));

        return self::EXIT_SUCCESS;
    }

    /** @param string[] $arguments */
    private function sign(array $arguments): int
    {
        if ($this->isHelpRequested($arguments)) {
            fwrite($this->stdout, $this->signUsage());

            return self::EXIT_SUCCESS;
        }

        $options = (new OptionParser(
            ['key', 'script', 'format', 'era', 'out', 'line-ending', 'asset-id'],
            ['help', 'token-only'],
            [
                'k' => 'key',
                's' => 'script',
                'f' => 'format',
                'o' => 'out',
                'h' => 'help',
            ]
        ))->parse($arguments);

        if (isset($options['format'], $options['era'])) {
            throw new InvalidArgumentException('Use either --format or --era, not both.');
        }

        $keyPath = $this->requireValue($options, 'key');
        $scriptPath = $this->requireValue($options, 'script');
        $format = $options['format'] ?? $options['era'] ?? Era::V2019;

        $lineEnding = match ($options['line-ending'] ?? 'crlf') {
            'crlf' => SigningOptions::LINE_ENDING_CRLF,
            'lf' => SigningOptions::LINE_ENDING_LF,
            default => throw new InvalidArgumentException(
                '--line-ending must be "crlf" or "lf".'
            ),
        };

        $script = $this->readInput($scriptPath, 'script');
        $privateKeyPem = $this->readInput($keyPath, 'private key');

        $signingOptions = new SigningOptions(
            Signer::resolveFormat($format),
            $lineEnding,
            isset($options['asset-id']) ? (string) $options['asset-id'] : null,
            !isset($options['token-only'])
        );

        $output = Signer::signWithOptions($script, $privateKeyPem, $signingOptions);

        if (isset($options['out'])) {
            $this->writeFile((string) $options['out'], $output);
        } else {
            fwrite($this->stdout, $output);
        }

        return self::EXIT_SUCCESS;
    }

    /** @param string[] $arguments */
    private function verify(array $arguments): int
    {
        if ($this->isHelpRequested($arguments)) {
            fwrite($this->stdout, $this->verifyUsage());

            return self::EXIT_SUCCESS;
        }

        $options = (new OptionParser(
            ['signed', 'public-key', 'payload'],
            ['help'],
            ['h' => 'help']
        ))->parse($arguments);

        $signedPath = $this->requireValue($options, 'signed');
        $publicKey = $this->requireValue($options, 'public-key');
        $signed = $this->readInput($signedPath, 'signed script');

        $valid = isset($options['payload'])
            ? Verifier::verifyPayload(
                $this->readInput((string) $options['payload'], 'payload'),
                Verifier::extractToken($signed),
                $publicKey
            )
            : Verifier::verify($signed, $publicKey);

        fwrite($this->stdout, $valid ? "Signature is valid.\n" : "Signature is invalid.\n");

        return $valid ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
    }

    private function printHelp(): int
    {
        fwrite($this->stdout, "rbxsign - Roblox key generation and script signing\n\n"
            . "Usage:\n"
            . "  rbxsign keys:generate [options]\n"
            . "  rbxsign sign [options]\n"
            . "  rbxsign verify [options]\n\n"
            . $this->keyGenerationUsage()
            . "\n"
            . $this->signUsage()
            . "\n"
            . $this->verifyUsage());

        return self::EXIT_SUCCESS;
    }

    private function keyGenerationUsage(): string
    {
        return "keys:generate options:\n"
            . "  -b, --bits <1024|2048>   Key size (default: 2048)\n"
            . "  --out-dir <dir>          Output directory (default: .)\n"
            . "  --priv-out <file>        Private key path\n"
            . "  --pub-out <file>         Public key path\n"
            . "  --blob-out <file>        Public key blob path\n"
            . "  --force                  Overwrite existing files\n"
            . "  -h, --help               Show this help\n";
    }

    private function signUsage(): string
    {
        return "sign options:\n"
            . "  -k, --key <file>         Private key PEM (required)\n"
            . "  -s, --script <file>      Lua script, or - for stdin (required)\n"
            . "  -f, --format <format>    classic|rbxsig|rbxsig2|rbxsig4\n"
            . "  --era <era>              pre_2012|v2013|v2017|v2018|v2019|v2020\n"
            . "  -o, --out <file>         Output file (default: stdout)\n"
            . "  --line-ending <crlf|lf>  Payload line ending (default: crlf)\n"
            . "  --asset-id <id>          Include --rbxassetid%id%\n"
            . "  --token-only             Output only the signature token\n"
            . "  -h, --help               Show this help\n";
    }

    private function verifyUsage(): string
    {
        return "verify options:\n"
            . "  --signed <file>          Signed script, or - for stdin (required)\n"
            . "  --public-key <file>      Public key PEM (required)\n"
            . "  --payload <file>         Payload for token-only signatures\n"
            . "  -h, --help               Show this help\n";
    }

    /** @param string[] $arguments */
    private function isHelpRequested(array $arguments): bool
    {
        return in_array('--help', $arguments, true) || in_array('-h', $arguments, true);
    }

    /**
     * @param array<string, string|true> $options
     */
    private function requireValue(array $options, string $name): string
    {
        $value = $options[$name] ?? null;

        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException("--{$name} is required");
        }

        return $value;
    }

    private function readInput(string $path, string $label): string
    {
        if ($path === '-') {
            $contents = stream_get_contents(STDIN);

            if ($contents === false) {
                throw new \RuntimeException("Unable to read {$label} from stdin");
            }

            return $contents;
        }

        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException("Unable to read {$label} from: {$path}");
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new \RuntimeException("Unable to read {$label} from: {$path}");
        }

        return $contents;
    }

    private function writeFile(string $path, string $contents): void
    {
        $written = file_put_contents($path, $contents);

        if ($written === false || $written !== strlen($contents)) {
            throw new \RuntimeException("Cannot write {$path}");
        }
    }
}
