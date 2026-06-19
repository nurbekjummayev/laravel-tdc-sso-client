<?php

declare(strict_types=1);
use Illuminate\Contracts\Console\Kernel;

it('is registered as an artisan command', function (): void {
    expect(array_keys($this->app[Kernel::class]->all()))
        ->toContain('sso:install');
});

it('fails gracefully when the oauth_clients table is missing', function (): void {
    // The in-memory test database has no Passport tables; the command must
    // refuse rather than blow up, telling the user to migrate first.
    $this->artisan('sso:install')->assertFailed();
});
