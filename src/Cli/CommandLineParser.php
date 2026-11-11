<?php

declare(strict_types=1);

namespace RobloxSigner\Cli;

use InvalidArgumentException;
use RobloxSigner\Keys\KeyGenerationRequest;
use RobloxSigner\Keys\KeySize;
use RobloxSigner\Keys\OutputFileNames;

final class CommandLineParser
{
    private const OPTION_BITS = 'bits';
    private const OPTION_OUT_DIR = 'out-dir';
    private const OPTION_PRIVATE_OUT = 'priv-out';
    private const OPTION_PUBLIC_OUT = 'pub-out';
    private const OPTION_BLOB_OUT = 'blob-out';
    private const OPTION_FORCE = 'force';
    private const OPTION_HELP = 'help';

    private const VALUE_OPTIONS = [
        self::OPTION_BITS,
        self::OPTION_OUT_DIR,
        self::OPTION_PRIVATE_OUT,
        self::OPTION_PUBLIC_OUT,
        self::OPTION_BLOB_OUT,
    ];

    private const FLAG_OPTIONS = [
        self::OPTION_FORCE,
        self::OPTION_HELP,
    ];

    private const SHORT_ALIASES = [
        'b' => self::OPTION_BITS,
        'h' => self::OPTION_HELP,
    ];

    /** @param string[] $arguments */
    public function parse(array $arguments): KeyGenerationRequest
    {
        $options = (new OptionParser(
            self::VALUE_OPTIONS,
            self::FLAG_OPTIONS,
            self::SHORT_ALIASES
        ))->parse($arguments);

        $keySize = KeySize::fromBits(
            $this->parseBits($options[self::OPTION_BITS] ?? (string) KeySize::BITS_2048)
        );

        $defaults = OutputFileNames::fromDirectory($options[self::OPTION_OUT_DIR] ?? '.');

        $fileNames = new OutputFileNames(
            $options[self::OPTION_PRIVATE_OUT] ?? $defaults->getPrivateKey(),
            $options[self::OPTION_PUBLIC_OUT] ?? $defaults->getPublicKey(),
            $options[self::OPTION_BLOB_OUT] ?? $defaults->getPublicKeyBlob()
        );

        return new KeyGenerationRequest(
            $keySize,
            $fileNames,
            isset($options[self::OPTION_FORCE])
        );
    }

    private function parseBits(string $bits): int
    {
        $parsedBits = filter_var($bits, FILTER_VALIDATE_INT);

        if ($parsedBits === false) {
            throw new InvalidArgumentException("Invalid value for --bits: {$bits}");
        }

        return $parsedBits;
    }
}
