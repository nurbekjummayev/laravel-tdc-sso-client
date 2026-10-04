<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Providers;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use Nurbekjummayev\LaravelTdcSsoClient\Auth\ActiveColumnGate;
use Nurbekjummayev\LaravelTdcSsoClient\Console\InstallSsoCommand;
use Nurbekjummayev\LaravelTdcSsoClient\Contracts\LoginGate;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware\EnsureUserIsActive;
use Nurbekjummayev\LaravelTdcSsoClient\Services\AuthLogger;
use Nurbekjummayev\LaravelTdcSsoClient\Services\PinManager;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoClient;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoService;
use Nurbekjummayev\LaravelTdcSsoClient\Services\UnlockTokenManager;
use Nurbekjummayev\LaravelTdcSsoClient\Support\SsoCookieFactory;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsoServiceProvider extends PackageServiceProvider
{
    /**
     * Configure the package: name, config file, and migrations.
     *
     * Ships only the package's OWN tables: sso_auth_logs, sso_lock_pins and
     * sso_unlock_tokens. The Passport oauth_* tables are NOT bundled — they are
     * Passport's own schema (publish via `php artisan passport:install`). The
     * spatie/permission table is bundled, guarded with Schema::hasTable so it
     * is skipped when the host app already installed it. Routes are registered
     * manually in bootingPackage() to preserve the configured prefix +
     * middleware group.
     */
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-tdc-sso-client')
            ->hasConfigFile('sso')
            ->discoversMigrations()
            ->runsMigrations()
            ->hasCommand(InstallSsoCommand::class);
    }

    /**
     * Register the package's service bindings.
     */
    public function packageRegistered(): void
    {
        $this->app->singleton(SsoClient::class);
        $this->app->singleton(AuthLogger::class);
        $this->app->singleton(UnlockTokenManager::class);
        $this->app->singleton(PinManager::class);
        $this->app->singleton(SsoService::class);
        $this->app->singleton(SsoCookieFactory::class);

        $this->app->singleton(LoginGate::class, function ($app): LoginGate {
            $gate = config('sso.login_gate') ?: ActiveColumnGate::class;

            return $app->make($gate);
        });
    }

    /**
     * Bootstrap the package's routes.
     */
    public function bootingPackage(): void
    {
        Route::aliasMiddleware('sso.active', EnsureUserIsActive::class);

        $this->registerRoutes();
    }

    /**
     * Apply Passport session-token lifetime after the package boots.
     */
    public function packageBooted(): void
    {
        Passport::personalAccessTokensExpireIn(
            Carbon::now()->addMinutes((int) config('sso.token_expiry_minutes', 60)),
        );
    }

    /**
     * Register the SSO BFF routes using the configured prefix and middleware.
     */
    private function registerRoutes(): void
    {
        if (! config('sso.routes.enabled', true)) {
            return;
        }

        Route::prefix((string) config('sso.routes.prefix', 'api/auth/sso'))
            ->middleware((array) config('sso.routes.middleware', ['api']))
            ->group($this->routesPath());
    }

    private function routesPath(): string
    {
        return __DIR__.'/../../routes/api.php';
    }
}
