<?php

declare(strict_types=1);

use Laravel\Passport\Passport;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoUnlockToken;
use Nurbekjummayev\LaravelTdcSsoClient\Services\PinManager;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoService;
use Nurbekjummayev\LaravelTdcSsoClient\Services\UnlockTokenManager;
use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\FullStack;
use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\GateUser;

beforeEach(fn () => FullStack::boot());

it('logs an active user in and sets both cookies', function (): void {
    FullStack::user();

    $this->postJson('api/auth/sso/callback', FullStack::fakeProvider())
        ->assertOk()
        ->assertCookie('session_token')
        ->assertCookie('unlock_token');
});

it('rejects an inactive user on callback before any token is minted', function (): void {
    $user = FullStack::user(['is_active' => false]);

    $response = $this->postJson('api/auth/sso/callback', FullStack::fakeProvider())
        ->assertForbidden()
        ->assertJsonPath('code', 'account_inactive')
        ->assertCookieExpired('session_token')
        ->assertCookieExpired('unlock_token');

    expect($user->tokens()->where('revoked', false)->count())->toBe(0)
        ->and(SsoUnlockToken::query()->where('user_id', $user->id)->count())->toBe(0)
        ->and(SsoAuthLog::query()->where('event', 'login_denied')->first()->meta)
        ->toBe(['reason' => 'account_inactive']);
});

it('rejects a soft-deleted user on callback instead of re-creating them', function (): void {
    config(['sso.auto_create_user' => true]);
    FullStack::user()->delete();

    $this->postJson('api/auth/sso/callback', FullStack::fakeProvider())
        ->assertForbidden()
        ->assertJsonPath('code', 'account_inactive');

    expect(GateUser::withTrashed()->count())->toBe(1);
});

it('returns account_not_registered for an unknown user', function (): void {
    $this->postJson('api/auth/sso/callback', FullStack::fakeProvider('99999999999999'))
        ->assertForbidden()
        ->assertJsonPath('code', 'account_not_registered');
});

it('allows everyone when active_column is null', function (): void {
    config(['sso.active_column' => null]);
    FullStack::user(['is_active' => false]);

    $this->postJson('api/auth/sso/callback', FullStack::fakeProvider())->assertOk();
});

it('rejects unlock for a deactivated user before checking the PIN', function (): void {
    $user = FullStack::user();
    app(PinManager::class)->set($user, '1234', '1234', null);
    $unlock = app(UnlockTokenManager::class)->issue($user->id);

    $user->update(['is_active' => false]);

    $this->withCredentials()
        ->withUnencryptedCookie('unlock_token', $unlock)
        ->postJson('api/auth/sso/unlock', ['pin' => '0000'])
        ->assertForbidden()
        ->assertJsonPath('code', 'account_inactive')
        ->assertCookieExpired('unlock_token');

    // The wrong PIN was never evaluated, and the unlock chain is dead.
    expect(app(PinManager::class)->has($user->id))->toBeTrue()
        ->and($user->fresh()->getAttribute('id'))->toBe($user->id)
        ->and(SsoUnlockToken::query()->whereNull('revoked_at')->count())->toBe(0);

    $this->assertDatabaseHas('sso_lock_pins', ['user_id' => $user->id, 'failed_attempts' => 0]);
});

it('rejects an authenticated request once the user is deactivated', function (): void {
    $user = FullStack::user();
    $user->createToken('spa');
    Passport::actingAs($user, [], 'api');

    $this->getJson('api/auth/sso/me')->assertOk()->assertJsonPath('data.user.has_pin', false);

    $user->update(['is_active' => false]);

    $this->getJson('api/auth/sso/me')
        ->assertForbidden()
        ->assertJsonPath('code', 'account_inactive');

    expect($user->tokens()->where('revoked', false)->count())->toBe(0);
});

it('revokeAll kills every Passport and unlock token, or only SSO ones', function (): void {
    $user = FullStack::user();
    $user->createToken('spa');
    $user->createToken('integration');
    app(UnlockTokenManager::class)->issue($user->id);

    app(SsoService::class)->revokeAll($user, onlySso: true);

    expect($user->tokens()->where('revoked', false)->pluck('name')->all())->toBe(['integration'])
        ->and(SsoUnlockToken::query()->whereNull('revoked_at')->count())->toBe(0);

    app(SsoService::class)->revokeAll($user);

    expect($user->tokens()->where('revoked', false)->count())->toBe(0);
});

it('registers the sso.active middleware alias', function (): void {
    expect(app('router')->getMiddleware())->toHaveKey('sso.active');
});

it('still unlocks an active user with the right PIN', function (): void {
    $user = FullStack::user();
    app(PinManager::class)->set($user, '1234', '1234', null);
    $unlock = app(UnlockTokenManager::class)->issue($user->id);

    $this->withCredentials()
        ->withUnencryptedCookie('unlock_token', $unlock)
        ->postJson('api/auth/sso/unlock', ['pin' => '1234'])
        ->assertOk()
        ->assertCookie('session_token');
});

it('lets a freshly auto-provisioned user through the gate (DB defaults loaded)', function (): void {
    config(['sso.auto_create_user' => true]);

    $this->postJson('api/auth/sso/callback', FullStack::fakeProvider())->assertOk();

    expect(GateUser::query()->first()->is_active)->toBeTrue();
});
