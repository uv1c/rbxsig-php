<?php

declare(strict_types=1);

namespace RobloxSigner\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobloxSigner\Era;
use RobloxSigner\SignatureFormat;

final class EraTest extends TestCase
{
    #[DataProvider('formatProvider')]
    public function testSignatureFormat(Era $era, SignatureFormat $expectedFormat): void
    {
        self::assertSame($expectedFormat, $era->signatureFormat());
    }

    /** @return array<string, array{Era, SignatureFormat}> */
    public static function formatProvider(): array
    {
        return [
            'pre_2012' => [Era::PRE_2012, SignatureFormat::CLASSIC],
            'v2013' => [Era::V2013, SignatureFormat::RBXSIG],
            'v2017' => [Era::V2017, SignatureFormat::RBXSIG],
            'v2018' => [Era::V2018, SignatureFormat::RBXSIG2],
            'v2019' => [Era::V2019, SignatureFormat::RBXSIG2],
            'v2020' => [Era::V2020, SignatureFormat::RBXSIG4],
        ];
    }

    public function testCanBeCreatedFromItsValue(): void
    {
        self::assertSame(Era::V2019, Era::from('v2019'));
        self::assertNull(Era::tryFrom('v1999'));
    }
}
