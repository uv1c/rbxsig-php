<?php

declare(strict_types=1);

namespace RobloxSigner\Tests\Keys;

use PHPUnit\Framework\TestCase;
use RobloxSigner\Keys\OutputFileNames;

final class OutputFileNamesTest extends TestCase
{
    public function testDefaultNamesAreExact(): void
    {
        $names = new OutputFileNames();

        self::assertSame('PrivateKey.pem', $names->getPrivateKey());
        self::assertSame('PublicKey.pem', $names->getPublicKey());
        self::assertSame('PublicKeyBlob.txt', $names->getPublicKeyBlob());
    }

    public function testFromDirectory(): void
    {
        $names = OutputFileNames::fromDirectory('keys');
        $separator = DIRECTORY_SEPARATOR;

        self::assertSame("keys{$separator}PrivateKey.pem", $names->getPrivateKey());
        self::assertSame("keys{$separator}PublicKey.pem", $names->getPublicKey());
        self::assertSame("keys{$separator}PublicKeyBlob.txt", $names->getPublicKeyBlob());
    }

    public function testFromDirectoryNormalizesTrailingSeparators(): void
    {
        self::assertSame(
            OutputFileNames::fromDirectory('keys')->getPrivateKey(),
            OutputFileNames::fromDirectory('keys' . DIRECTORY_SEPARATOR)->getPrivateKey()
        );
    }

    public function testFromEmptyDirectoryUsesBareNames(): void
    {
        $names = OutputFileNames::fromDirectory('');

        self::assertSame('PrivateKey.pem', $names->getPrivateKey());
        self::assertSame('PublicKey.pem', $names->getPublicKey());
        self::assertSame('PublicKeyBlob.txt', $names->getPublicKeyBlob());
    }

    public function testFromRootDirectoryKeepsSeparator(): void
    {
        $names = OutputFileNames::fromDirectory('/');

        self::assertSame('/PrivateKey.pem', $names->getPrivateKey());
        self::assertSame('/PublicKey.pem', $names->getPublicKey());
        self::assertSame('/PublicKeyBlob.txt', $names->getPublicKeyBlob());
    }

    public function testFromWindowsDriveRootKeepsSeparator(): void
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            self::markTestSkipped('Windows drive-root behavior.');
        }

        $names = OutputFileNames::fromDirectory('C:\\');

        self::assertSame('C:\\PrivateKey.pem', $names->getPrivateKey());
        self::assertSame('C:\\PublicKey.pem', $names->getPublicKey());
        self::assertSame('C:\\PublicKeyBlob.txt', $names->getPublicKeyBlob());
    }
}
