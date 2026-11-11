<?php

declare(strict_types=1);

namespace RobloxSigner;

/**
 * Signature prefixes used by Roblox clients over time.
 *
 * - CLASSIC: %<base64>%
 * - RBXSIG:  --rbxsig%<base64>%
 * - RBXSIG2: --rbxsig2%<base64>%
 * - RBXSIG4: --rbxsig4%<base64>%
 */
enum SignatureFormat: string
{
    case CLASSIC = 'classic';
    case RBXSIG = 'rbxsig';
    case RBXSIG2 = 'rbxsig2';
    case RBXSIG4 = 'rbxsig4';

    /**
     * Returns the signature prefix for this format, without the % delimiters.
     */
    public function prefix(): string
    {
        return match ($this) {
            self::CLASSIC => '',
            self::RBXSIG => '--rbxsig',
            self::RBXSIG2 => '--rbxsig2',
            self::RBXSIG4 => '--rbxsig4',
        };
    }

    /**
     * Key size commonly paired with this format.
     *
     * This is advisory only; some clients accept other sizes. It is used for
     * warnings, not hard validation.
     */
    public function recommendedKeyBits(): int
    {
        return match ($this) {
            self::CLASSIC, self::RBXSIG => 1024,
            self::RBXSIG2, self::RBXSIG4 => 2048,
        };
    }
}
