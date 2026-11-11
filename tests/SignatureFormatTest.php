<?php

declare(strict_types=1);

namespace RobloxSigner\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobloxSigner\SignatureFormat;

final class SignatureFormatTest extends TestCase
{
    #[DataProvider('prefixProvider')]
    public function testPrefix(SignatureFormat $format, string $expectedPrefix): void
    {
        self::assertSame($expectedPrefix, $format->prefix());
    }

    /** @return array<string, array{SignatureFormat, string}> */
    public static function prefixProvider(): array
    {
        return [
            'classic' => [SignatureFormat::CLASSIC, ''],
            'rbxsig' => [SignatureFormat::RBXSIG, '--rbxsig'],
            'rbxsig2' => [SignatureFormat::RBXSIG2, '--rbxsig2'],
            'rbxsig4' => [SignatureFormat::RBXSIG4, '--rbxsig4'],
        ];
    }

    #[DataProvider('keyBitsProvider')]
    public function testRecommendedKeyBits(SignatureFormat $format, int $expectedBits): void
    {
        self::assertSame($expectedBits, $format->recommendedKeyBits());
    }

    /** @return array<string, array{SignatureFormat, int}> */
    public static function keyBitsProvider(): array
    {
        return [
            'classic' => [SignatureFormat::CLASSIC, 1024],
            'rbxsig' => [SignatureFormat::RBXSIG, 1024],
            'rbxsig2' => [SignatureFormat::RBXSIG2, 2048],
            'rbxsig4' => [SignatureFormat::RBXSIG4, 2048],
        ];
    }

    public function testCanBeCreatedFromItsValue(): void
    {
        self::assertSame(SignatureFormat::RBXSIG4, SignatureFormat::from('rbxsig4'));
        self::assertNull(SignatureFormat::tryFrom('unknown'));
    }
}
