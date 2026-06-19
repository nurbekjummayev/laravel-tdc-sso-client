<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoClient;

it('unwraps the enveloped userinfo payload', function (): void {
    Http::fake([
        'sso.example.test/oauth/userinfo' => Http::response([
            'msg' => 'OK',
            'success' => true,
            'data' => ['pinfl' => '12345678901234', 'full_name' => 'Test User'],
        ]),
    ]);

    $info = app(SsoClient::class)->fetchUserInfo('sso-access-token');

    expect($info)
        ->toHaveKey('pinfl', '12345678901234')
        ->toHaveKey('full_name', 'Test User');
});

it('falls back to the whole body when userinfo is not enveloped', function (): void {
    Http::fake([
        'sso.example.test/oauth/userinfo' => Http::response(['pinfl' => '99999999999999']),
    ]);

    $info = app(SsoClient::class)->fetchUserInfo('sso-access-token');

    expect($info)->toHaveKey('pinfl', '99999999999999');
});

it('throws when the token exchange returns no access token', function (): void {
    Http::fake([
        'sso.example.test/oauth/token' => Http::response(['token_type' => 'Bearer']),
    ]);

    expect(fn () => app(SsoClient::class)->exchangeCode('code', 'verifier'))
        ->toThrow(RuntimeException::class);
});
