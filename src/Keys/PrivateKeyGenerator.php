<?php

declare(strict_types=1);

namespace RobloxSigner\Keys;

interface PrivateKeyGenerator
{
    public function generate(KeySize $keySize): RsaPrivateKey;
}
