<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;

it('is registered as an artisan command', function (): void {
    // sso:install orchestrates Passport's own commands (vendor:publish, migrate,
    // passport:keys) plus client creation; the pieces are Passport's tested code,
    // so here we just assert the command is wired into the app.
    expect(array_keys($this->app[Kernel::class]->all()))
        ->toContain('sso:install');
});
