<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Cli;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Cli\OptionParser;

final class OptionParserTest extends TestCase
{
    private OptionParser $parser;

    protected function setUp(): void
    {
        $this->parser = new OptionParser(
            ['out', 'key'],
            ['force', 'help'],
            ['o' => 'out', 'k' => 'key', 'f' => 'force', 'h' => 'help']
        );
    }

    public function testParsesLongOptionWithSpace(): void
    {
        self::assertSame(['out' => 'file.txt'], $this->parser->parse(['--out', 'file.txt']));
    }

    public function testParsesLongOptionWithEquals(): void
    {
        self::assertSame(['out' => 'file.txt'], $this->parser->parse(['--out=file.txt']));
    }

    public function testParsesShortOptionWithSpace(): void
    {
        self::assertSame(['out' => 'file.txt'], $this->parser->parse(['-o', 'file.txt']));
    }

    public function testParsesShortOptionAttached(): void
    {
        self::assertSame(['out' => 'file.txt'], $this->parser->parse(['-ofile.txt']));
    }

    public function testParsesShortOptionWithEquals(): void
    {
        self::assertSame(['out' => 'file.txt'], $this->parser->parse(['-o=file.txt']));
    }

    public function testParsesFlags(): void
    {
        self::assertSame(
            ['force' => true, 'help' => true],
            $this->parser->parse(['--force', '-h'])
        );
    }

    public function testParsesDashAsOptionValue(): void
    {
        self::assertSame(['out' => '-'], $this->parser->parse(['--out', '-']));
    }

    public function testLaterValueWins(): void
    {
        self::assertSame(
            ['out' => 'second.txt'],
            $this->parser->parse(['--out', 'first.txt', '--out', 'second.txt'])
        );
    }

    public function testDoubleDashAloneIsAccepted(): void
    {
        self::assertSame([], $this->parser->parse(['--']));
    }

    public function testUnknownLongOptionThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown option: --unknown');

        $this->parser->parse(['--unknown']);
    }

    public function testUnknownShortOptionThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown option: -z');

        $this->parser->parse(['-z']);
    }

    public function testMissingValueAtEndThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Option --out requires a value');

        $this->parser->parse(['--out']);
    }

    public function testMissingValueBeforeAnotherOptionThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Option --out requires a value');

        $this->parser->parse(['--out', '--force']);
    }

    public function testFlagWithValueThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Option --force does not take a value');

        $this->parser->parse(['--force=yes']);
    }

    public function testPositionalArgumentThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unexpected argument: stray');

        $this->parser->parse(['stray']);
    }

    public function testArgumentsAfterDoubleDashThrow(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unexpected argument: stray');

        $this->parser->parse(['--', 'stray']);
    }
}
