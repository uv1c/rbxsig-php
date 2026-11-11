<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Cli;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Cli\CommandLineParser;
use RobloxSigner\Keys\KeySize;
use RobloxSigner\Keys\OutputFileNames;

final class CommandLineParserTest extends TestCase
{
    private CommandLineParser $parser;

    protected function setUp(): void
    {
        $this->parser = new CommandLineParser();
    }

    public function testDefaultsTo2048BitsAndExactNames(): void
    {
        $request = $this->parser->parse([]);
        $defaults = OutputFileNames::fromDirectory('.');

        self::assertSame(KeySize::BITS_2048, $request->getKeySize()->getBits());
        self::assertSame($defaults->getPrivateKey(), $request->getFileNames()->getPrivateKey());
        self::assertSame($defaults->getPublicKey(), $request->getFileNames()->getPublicKey());
        self::assertSame($defaults->getPublicKeyBlob(), $request->getFileNames()->getPublicKeyBlob());
        self::assertFalse($request->shouldOverwrite());
    }

    public function testParsesAllOptions(): void
    {
        $request = $this->parser->parse([
            '--bits', '1024',
            '--out-dir', 'keys',
            '--priv-out', 'custom/private.pem',
            '--pub-out', 'custom/public.pem',
            '--blob-out', 'custom/blob.txt',
            '--force',
        ]);

        self::assertSame(1024, $request->getKeySize()->getBits());
        self::assertSame('custom/private.pem', $request->getFileNames()->getPrivateKey());
        self::assertSame('custom/public.pem', $request->getFileNames()->getPublicKey());
        self::assertSame('custom/blob.txt', $request->getFileNames()->getPublicKeyBlob());
        self::assertTrue($request->shouldOverwrite());
    }

    public function testShortBitsOption(): void
    {
        self::assertSame(1024, $this->parser->parse(['-b1024'])->getKeySize()->getBits());
        self::assertSame(1024, $this->parser->parse(['-b', '1024'])->getKeySize()->getBits());
        self::assertSame(1024, $this->parser->parse(['--bits=1024'])->getKeySize()->getBits());
    }

    public function testOutDirBuildsDefaultNames(): void
    {
        $request = $this->parser->parse(['--out-dir', 'keys']);
        $separator = DIRECTORY_SEPARATOR;

        self::assertSame("keys{$separator}PrivateKey.pem", $request->getFileNames()->getPrivateKey());
        self::assertSame("keys{$separator}PublicKey.pem", $request->getFileNames()->getPublicKey());
        self::assertSame("keys{$separator}PublicKeyBlob.txt", $request->getFileNames()->getPublicKeyBlob());
    }

    public function testUnsupportedKeySizeThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->parser->parse(['--bits', '3072']);
    }

    public function testNonNumericBitsThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid value for --bits');

        $this->parser->parse(['--bits', 'large']);
    }
}
