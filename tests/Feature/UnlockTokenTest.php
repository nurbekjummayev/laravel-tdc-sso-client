<?php

declare(strict_types=1);

use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidUnlockTokenException;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoUnlockToken;
use Nurbekjummayev\LaravelTdcSsoClient\Services\UnlockTokenManager;

beforeEach(function (): void {
    (require __DIR__.'/../../database/migrations/2026_06_19_000002_create_sso_unlock_tokens_table.php')->up();
});

it('issues a token that then verifies', function (): void {
    $manager = app(UnlockTokenManager::class);

    $token = $manager->issue(42);

    $record = $manager->verify($token);

    expect($record->user_id)->toBe(42)
        ->and($record->isValid())->toBeTrue();
});

it('rotates a token: the new one works and the old is revoked', function (): void {
    $manager = app(UnlockTokenManager::class);

    $token = $manager->issue(42);
    $record = $manager->verify($token);
    $oldId = $record->id;

    $newToken = $manager->rotate($record);

    // The new token is valid...
    expect($manager->verify($newToken)->user_id)->toBe(42);

    // ...and the old row is revoked (checked at the DB level, so we don't
    // trip the replay/theft detection that verifying the old token would).
    expect(SsoUnlockToken::query()->find($oldId)->isRevoked())->toBeTrue();
});

it('rotation preserves the absolute expiry (no sliding)', function (): void {
    $manager = app(UnlockTokenManager::class);

    $token = $manager->issue(42);
    $original = $manager->verify($token);
    $originalExpiry = $original->expires_at->toDateTimeString();

    $newToken = $manager->rotate($original);

    expect($manager->verify($newToken)->expires_at->toDateTimeString())->toBe($originalExpiry);
});

it('treats a replayed (revoked) token as theft and revokes the whole chain', function (): void {
    $manager = app(UnlockTokenManager::class);

    $token = $manager->issue(42);
    $record = $manager->verify($token);
    $manager->rotate($record); // old token now revoked

    // Replaying the revoked token must fail AND revoke every active token.
    expect(fn () => $manager->verify($token))->toThrow(InvalidUnlockTokenException::class);

    $active = SsoUnlockToken::query()->where('user_id', 42)->whereNull('revoked_at')->count();

    expect($active)->toBe(0);
});

it('rejects an unknown token', function (): void {
    expect(fn () => app(UnlockTokenManager::class)->verify('does-not-exist'))
        ->toThrow(InvalidUnlockTokenException::class);
});
