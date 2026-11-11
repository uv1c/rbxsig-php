<?php

declare(strict_types=1);

namespace RobloxSigner\Cli;

use InvalidArgumentException;

/**
 * Small, strict option parser for the CLI.
 *
 * Supports:
 * - --name value
 * - --name=value
 * - -x value
 * - -xvalue
 * - boolean flags
 */
final class OptionParser
{
    /**
     * @param string[] $valueOptions
     * @param string[] $flagOptions
     * @param array<string, string> $shortAliases
     */
    public function __construct(
        private readonly array $valueOptions,
        private readonly array $flagOptions = [],
        private readonly array $shortAliases = []
    ) {
    }

    /**
     * @param string[] $arguments
     * @return array<string, string|true>
     */
    public function parse(array $arguments): array
    {
        $options = [];
        $count = count($arguments);

        for ($position = 0; $position < $count; $position++) {
            $argument = $arguments[$position];

            if ($argument === '--') {
                if ($position + 1 < $count) {
                    throw new InvalidArgumentException(
                        "Unexpected argument: {$arguments[$position + 1]}"
                    );
                }

                break;
            }

            [$name, $inlineValue] = $this->splitOption($argument);

            if ($this->isFlag($name)) {
                if ($inlineValue !== null) {
                    throw new InvalidArgumentException(
                        "Option --{$name} does not take a value"
                    );
                }

                $options[$name] = true;
                continue;
            }

            if ($inlineValue === null) {
                $next = $arguments[$position + 1] ?? null;

                if ($next === null || $this->isOptionToken($next)) {
                    throw new InvalidArgumentException(
                        "Option --{$name} requires a value"
                    );
                }

                $inlineValue = $next;
                $position++;
            }

            $options[$name] = $inlineValue;
        }

        return $options;
    }

    /** @return array{0: string, 1: ?string} */
    private function splitOption(string $argument): array
    {
        if (str_starts_with($argument, '--')) {
            [$name, $value] = array_pad(explode('=', substr($argument, 2), 2), 2, null);

            return [$this->requireKnownOption($name), $value];
        }

        if (str_starts_with($argument, '-') && strlen($argument) > 1) {
            $alias = $argument[1];
            $name = $this->shortAliases[$alias]
                ?? throw new InvalidArgumentException("Unknown option: -{$alias}");
            $value = strlen($argument) > 2 ? substr($argument, 2) : null;

            if ($value !== null && str_starts_with($value, '=')) {
                $value = substr($value, 1);
            }

            return [$name, $value];
        }

        throw new InvalidArgumentException("Unexpected argument: {$argument}");
    }

    private function requireKnownOption(string $name): string
    {
        if (in_array($name, $this->valueOptions, true)
            || in_array($name, $this->flagOptions, true)) {
            return $name;
        }

        throw new InvalidArgumentException("Unknown option: --{$name}");
    }

    private function isFlag(string $name): bool
    {
        return in_array($name, $this->flagOptions, true);
    }

    private function isOptionToken(string $argument): bool
    {
        return str_starts_with($argument, '-') && $argument !== '-';
    }
}
