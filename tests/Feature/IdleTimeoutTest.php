<?php

declare(strict_types=1);

use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\FullStack;

beforeEach(fn () => FullStack::boot());

/**
 * Real bearer auth through Passport's TokenGuard, so the user carries the
 * Passport 13 AccessToken wrapper (no getKey()) rather than an Eloquent Token.
 */
it('tracks activity and revokes an idle token', function (): void {
    config(['sso.idle.timeout' => 15]);
    $user = FullStack::user();
    $result = $user->createToken('spa');
    $start = time();

    $call = fn (int $at) => $this->withServerVariables(['REQUEST_TIME' => $at])
        ->withToken($result->accessToken)
        ->getJson('api/auth/sso/me');

    $call($start)->assertOk();
    expect(cache()->get('sso:activity:'.$result->accessTokenId))->toBe($start);

    $call($start + 60)->assertOk();

    $call($start + 60 + 16 * 60)
        ->assertUnauthorized()
        ->assertJsonPath('msg', 'Session expired due to inactivity');

    expect($user->tokens()->whereKey($result->accessTokenId)->value('revoked'))->toBeTruthy();
});

it('logs out with the AccessToken wrapper and records the token id', function (): void {
    $user = FullStack::user();
    $result = $user->createToken('spa');

    $this->withToken($result->accessToken)->postJson('api/auth/sso/logout')->assertOk();

    expect($user->tokens()->whereKey($result->accessTokenId)->value('revoked'))->toBeTruthy();
    $this->assertDatabaseHas('sso_auth_logs', ['event' => 'logout', 'token_id' => $result->accessTokenId]);
});
