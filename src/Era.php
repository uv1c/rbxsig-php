<?php

declare(strict_types=1);

namespace RobloxSigner;

/**
 * Represents Roblox client eras for script signature formats.
 *
 * The exact wrapper changed over time:
 * - Pre-2013:  %<base64>%
 * - 2013-2017: --rbxsig%<base64>%
 * - 2018-2020: --rbxsig2%<base64>%
 * - 2020+:     --rbxsig4%<base64>%
 *
 * Community documentation treats these as approximate era boundaries. The
 * actual client build is what matters. Use SignatureFormat directly when you
 * know exactly which wrapper the target client expects.
 */
enum Era: string
{
    /**
     * Pre-2013 clients.
     * Format: %<base64_signature>%
     */
    case PRE_2012 = 'pre_2012';

    /**
     * 2013-2016 era.
     * Format: --rbxsig%<base64_signature>%
     */
    case V2013 = 'v2013';

    /**
     * 2017 era.
     * Format: --rbxsig%<base64_signature>%
     */
    case V2017 = 'v2017';

    /**
     * 2018-2019 era.
     * Format: --rbxsig2%<base64_signature>%
     */
    case V2018 = 'v2018';

    /**
     * 2019 era.
     * Format: --rbxsig2%<base64_signature>%
     */
    case V2019 = 'v2019';

    /**
     * 2020+ era.
     * Format: --rbxsig4%<base64_signature>%
     */
    case V2020 = 'v2020';

    /**
     * Returns the signature format this era normally uses.
     */
    public function signatureFormat(): SignatureFormat
    {
        return match ($this) {
            self::PRE_2012 => SignatureFormat::CLASSIC,
            self::V2013, self::V2017 => SignatureFormat::RBXSIG,
            self::V2018, self::V2019 => SignatureFormat::RBXSIG2,
            self::V2020 => SignatureFormat::RBXSIG4,
        };
    }
}
