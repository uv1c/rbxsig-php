<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

final class Pkcs1PemEncoder
{
    private const PRIVATE_KEY_LABEL = 'RSA PRIVATE KEY';
    private const PUBLIC_KEY_LABEL = 'PUBLIC KEY';
    private const RSA_ENCRYPTION_OID = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    private const TWO_PRIME_VERSION = "\0";
    private const PEM_LINE_LENGTH = 64;
    private const LINE_FEED = "\n";

    public function __construct(private readonly DerEncoder $derEncoder)
    {
    }

    public function encodePrivateKey(RsaPrivateKey $privateKey): string
    {
        $publicKey = $privateKey->getPublicKey();
        $crtParameters = $privateKey->getCrtParameters();

        $integers = [
            self::TWO_PRIME_VERSION,
            $publicKey->getModulus(),
            $publicKey->getPublicExponent(),
            $privateKey->getPrivateExponent(),
            $crtParameters->getPrimeFactors()->getPrimeP(),
            $crtParameters->getPrimeFactors()->getPrimeQ(),
            $crtParameters->getExponents()->getExponentP(),
            $crtParameters->getExponents()->getExponentQ(),
            $crtParameters->getCoefficient(),
        ];

        return $this->wrapInPem(self::PRIVATE_KEY_LABEL, $this->encodeIntegerSequence($integers));
    }

    public function encodePublicKey(RsaPublicKey $publicKey): string
    {
        $integers = [$publicKey->getModulus(), $publicKey->getPublicExponent()];
        $rsaPublicKey = $this->encodeIntegerSequence($integers);
        $algorithmIdentifier = $this->derEncoder->encodeSequence(self::RSA_ENCRYPTION_OID . "\x05\x00");
        $subjectPublicKeyInfo = $this->derEncoder->encodeSequence(
            $algorithmIdentifier . $this->derEncoder->encodeBitString($rsaPublicKey)
        );

        return $this->wrapInPem(self::PUBLIC_KEY_LABEL, $subjectPublicKeyInfo);
    }

    /** @param string[] $unsignedBigEndianIntegers */
    private function encodeIntegerSequence(array $unsignedBigEndianIntegers): string
    {
        $encodedIntegers = array_map(
            fn (string $integer): string => $this->derEncoder->encodeInteger($integer),
            $unsignedBigEndianIntegers
        );

        return $this->derEncoder->encodeSequence(implode('', $encodedIntegers));
    }

    private function wrapInPem(string $label, string $der): string
    {
        $body = chunk_split(base64_encode($der), self::PEM_LINE_LENGTH, self::LINE_FEED);

        return "-----BEGIN {$label}-----" . self::LINE_FEED
            . $body
            . "-----END {$label}-----" . self::LINE_FEED;
    }
}
