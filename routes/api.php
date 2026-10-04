<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Controllers\SsoAuthLogController;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Controllers\SsoController;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware\AuthenticateSessionCookie;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware\EnforceIdleTimeout;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware\EnsureUserIsActive;

/*
| TDC-SSO (OAuth2 Authorization Code + PKCE), cookie-based BFF.
|
| The group prefix and base middleware are applied by the SsoServiceProvider
| from the package config (`sso.routes.*`), defaulting to the `api/auth/sso`
| prefix with the `api` middleware group.
|
| Public endpoints:
|   GET  redirect  — start the SSO flow
|   POST callback  — exchange code+state, set session + unlock cookies
|   POST unlock    — unlock cookie + PIN -> fresh session cookie (no auth: the
|                    session token is dead during a lock)
|
| Authenticated endpoints (session cookie -> Bearer -> auth -> login gate ->
| idle backstop):
|   GET  me        — current user + has_pin
|   POST set-pin   — set/change the screen-lock PIN
|   POST lock      — revoke session token, clear session cookie
|   POST logout    — revoke session + unlock tokens, clear both cookies
|   GET  logs/mine — the caller's auth history (sso.routes.logs.mine)
|   GET  logs      — every user's auth history, permission-gated
|                    (sso.routes.logs.admin)
*/
Route::get('redirect', [SsoController::class, 'redirect']);
Route::post('callback', [SsoController::class, 'callback']);
Route::post('unlock', [SsoController::class, 'unlock']);

Route::middleware(array_values(array_filter([
    AuthenticateSessionCookie::class,
    config('sso.routes.auth_middleware', 'auth:api'),
    EnsureUserIsActive::class,
    EnforceIdleTimeout::class,
])))->group(function (): void {
    Route::get('me', [SsoController::class, 'me']);
    Route::post('set-pin', [SsoController::class, 'setPin']);
    Route::post('lock', [SsoController::class, 'lock']);
    Route::post('logout', [SsoController::class, 'logout']);

    if ((bool) config('sso.routes.logs.mine', false)) {
        Route::get('logs/mine', [SsoAuthLogController::class, 'mine']);
    }

    if ((bool) config('sso.routes.logs.admin', false)) {
        Route::get('logs', [SsoAuthLogController::class, 'index'])
            ->middleware('can:'.config('sso.auth_log.permission', 'sso_logs.list'));
    }
});
