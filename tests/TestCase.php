<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Tests;

use Illuminate\Foundation\Application;
use Laravel\Passport\PassportServiceProvider;
use Nurbekjummayev\LaravelTdcSsoClient\Providers\SsoServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Spatie\Permission\PermissionServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            PassportServiceProvider::class,
            PermissionServiceProvider::class,
            SsoServiceProvider::class,
        ];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $config = $app['config'];

        $config->set('cache.default', 'array');

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Unit-level service tests create only the tables they need; auth-event
        // logging (which writes to sso_auth_logs) is disabled to keep them isolated.
        $config->set('sso.auth_log.enabled', false);

        $config->set('services.sso', [
            'base_url' => 'https://sso.example.test',
            'client_id' => 'client-123',
            'client_secret' => 'secret-xyz',
            'redirect_uri' => 'https://app.example.test/sso/callback',
            'scope' => '',
        ]);

        // Drop the route middleware in tests: the default `api` group requires a
        // named rate limiter the bare testbench app does not register.
        $config->set('sso.routes.middleware', []);
    }
}
