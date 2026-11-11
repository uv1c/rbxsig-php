<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

use RuntimeException;

final class KeyGenerator
{
    public function __construct(
        private readonly PrivateKeyGenerator $privateKeyGenerator,
        private readonly Pkcs1PemEncoder $pemEncoder,
        private readonly CspPublicKeyBlobEncoder $blobEncoder
    ) {
    }

    public static function create(?string $opensslConfigPath = null): self
    {
        return new self(
            new OpenSslPrivateKeyGenerator($opensslConfigPath),
            new Pkcs1PemEncoder(new DerEncoder()),
            new CspPublicKeyBlobEncoder()
        );
    }

    public function generate(KeySize $keySize): KeyPair
    {
        $privateKey = $this->privateKeyGenerator->generate($keySize);
        $publicKey = $privateKey->getPublicKey();

        $keyPair = new KeyPair(
            $keySize,
            $this->pemEncoder->encodePrivateKey($privateKey),
            $this->pemEncoder->encodePublicKey($publicKey),
            $this->blobEncoder->encode($publicKey)
        );

        $this->selfCheck($keyPair);

        return $keyPair;
    }

    /**
     * Verify that the PEMs and blob all describe the same key and that the
     * private key can actually produce a signature the public key accepts.
     */
    private function selfCheck(KeyPair $keyPair): void
    {
        $privateKey = @openssl_pkey_get_private($keyPair->getPrivateKeyPem());
        $publicKey = @openssl_pkey_get_public($keyPair->getPublicKeyPem());

        if ($privateKey === false || $publicKey === false) {
            throw new RuntimeException('Generated key pair could not be parsed by OpenSSL.');
        }

        $privateDetails = openssl_pkey_get_details($privateKey);
        $publicDetails = openssl_pkey_get_details($publicKey);

        if ($privateDetails === false || $publicDetails === false) {
            throw new RuntimeException('Generated key pair details could not be read.');
        }

        $privateModulus = ltrim($privateDetails['rsa']['n'], "\0");
        $publicModulus = ltrim($publicDetails['rsa']['n'], "\0");

        if ($privateModulus !== $publicModulus) {
            throw new RuntimeException('Generated private and public keys do not match.');
        }

        if (($privateDetails['bits'] ?? 0) !== $keyPair->getBits()) {
            throw new RuntimeException('Generated key size does not match the requested size.');
        }

        $blob = $keyPair->getPublicKeyBlob();

        if (strlen($blob) < 20) {
            throw new RuntimeException('Generated public key blob is malformed.');
        }

        $blobBits = unpack('V', substr($blob, 12, 4))[1] ?? 0;

        if ($blobBits < 1 || $blobBits > $keyPair->getBits()) {
            throw new RuntimeException('Generated public key blob has an invalid bit length.');
        }

        $blobModulus = ltrim(strrev(substr($blob, 20)), "\0");

        if ($blobModulus !== $privateModulus) {
            throw new RuntimeException('Generated public key blob does not match the key pair.');
        }

        $payload = 'rbxsig-key-self-check';
        $signature = '';

        $signed = openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA1);
        $verified = $signed
            ? openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA1)
            : 0;

        if ($verified !== 1) {
            throw new RuntimeException('Generated key pair failed the signing self-check.');
        }
    }
}
