<?php

declare(strict_types=1);

namespace RobloxSigner;

use InvalidArgumentException;

/**
 * Options for producing a signed script response.
 */
final class SigningOptions
{
    public const LINE_ENDING_CRLF = "\r\n";
    public const LINE_ENDING_LF = "\n";

    public function __construct(
        private readonly SignatureFormat $format = SignatureFormat::RBXSIG2,
        private readonly string $lineEnding = self::LINE_ENDING_CRLF,
        private readonly ?string $assetId = null,
        private readonly bool $includeScript = true
    ) {
        if (!in_array($this->lineEnding, [self::LINE_ENDING_CRLF, self::LINE_ENDING_LF], true)) {
            throw new InvalidArgumentException('Line ending must be "\r\n" or "\n".');
        }

        if ($this->assetId !== null && preg_match('/^\d+$/', $this->assetId) !== 1) {
            throw new InvalidArgumentException('Asset ID must contain digits only.');
        }
    }

    public function getFormat(): SignatureFormat
    {
        return $this->format;
    }

    public function getLineEnding(): string
    {
        return $this->lineEnding;
    }

    public function getAssetId(): ?string
    {
        return $this->assetId;
    }

    public function includesScript(): bool
    {
        return $this->includeScript;
    }
}
