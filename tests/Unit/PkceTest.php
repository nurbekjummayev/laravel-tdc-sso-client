<?php

declare(strict_types=1);

use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoClient;

it('derives the S256 code challenge from the RFC 7636 test vector', function (): void {
    // RFC 7636, Appendix B.
    $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    $expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    expect((new SsoClient)->codeChallenge($verifier))->toBe($expected);
});

it('generates a code challenge that is base64url with no padding', function (): void {
    $challenge = (new SsoClient)->codeChallenge('any-verifier-value');

    expect($challenge)
        ->not->toContain('+')
        ->not->toContain('/')
        ->not->toContain('=');
});

it('generates a high-entropy verifier within the RFC length bounds', function (): void {
    $verifier = (new SsoClient)->generateCodeVerifier();

    expect(strlen($verifier))->toBeGreaterThanOrEqual(43)->toBeLessThanOrEqual(128);
});
