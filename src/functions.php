<?php

declare(strict_types=1);

namespace RobloxSigner;

use RuntimeException;

/**
 * Sign a Lua script with minimal setup.
 *
 * The private key is resolved in this order:
 * 1. $privateKeyPath, when provided.
 * 2. The RBXSIG_PRIVATE_KEY environment variable.
 * 3. A conventional keys/ path relative to the current working directory:
 *    keys/legacy-1024/PrivateKey.pem for classic/rbxsig, or
 *    keys/PrivateKey.pem for rbxsig2/rbxsig4.
 */
function sign(
    string $script,
    Era|string|SignatureFormat $era = Era::V2019,
    ?string $privateKeyPath = null
): string {
    $format = Signer::resolveFormat($era);
    $resolvedKeyPath = $privateKeyPath ?? resolvePrivateKeyPath($format);

    return Signer::sign($script, $resolvedKeyPath, $format);
}

/**
 * Resolve the default private key path for a signature format.
 *
 * @internal
 */
function resolvePrivateKeyPath(SignatureFormat $format): string
{
    $environmentPath = getenv('RBXSIG_PRIVATE_KEY');

    if (is_string($environmentPath) && $environmentPath !== '') {
        return $environmentPath;
    }

    $workingDirectory = getcwd();
    $baseDirectory = $workingDirectory === false ? '.' : $workingDirectory;
    $candidates = $format->recommendedKeyBits() === 1024
        ? ['keys/legacy-1024/PrivateKey.pem', 'keys/PrivateKey.pem']
        : ['keys/PrivateKey.pem'];

    $absoluteCandidates = array_map(
        static fn (string $candidate): string => $baseDirectory . DIRECTORY_SEPARATOR . $candidate,
        $candidates
    );

    foreach ($absoluteCandidates as $candidate) {
        if (is_file($candidate) && is_readable($candidate)) {
            return $candidate;
        }
    }

    throw new RuntimeException(
        'No private key found. Pass it as the third argument to sign() or set RBXSIG_PRIVATE_KEY. '
        . 'Tried: ' . implode(', ', $absoluteCandidates)
    );
}
