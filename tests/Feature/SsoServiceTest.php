<?php

declare(strict_types=1);

use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoService;

it('rejects a callback with an unknown or expired state', function (): void {
    $service = app(SsoService::class);

    expect(fn () => $service->handleCallback('any-code', 'unknown-state'))
        ->toThrow(RuntimeException::class, 'Invalid or expired SSO state.');
});
