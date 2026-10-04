<?php

declare(strict_types=1);

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Passport;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog;
use Nurbekjummayev\LaravelTdcSsoClient\Services\AuthLogger;
use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\DeviceMetaResolver;
use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\ExtendedUserResource;
use Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures\FullStack;
use Spatie\Permission\Models\Permission;

beforeEach(fn () => FullStack::boot());

/**
 * Routes are registered at boot from config, so the toggles must be set
 * before the app boots.
 */
function enableLogRoutes(): void
{
    config(['sso.routes.logs.mine' => true, 'sso.routes.logs.admin' => true]);

    app('router')->setRoutes(new RouteCollection);
    Route::prefix('api/auth/sso')->group(__DIR__.'/../../routes/api.php');
}

function logFor(int $userId, AuthEvent $event, string $at = 'now'): SsoAuthLog
{
    $log = SsoAuthLog::query()->create(['user_id' => $userId, 'event' => $event->value]);
    $log->forceFill(['created_at' => Date::parse($at)])->save();

    return $log;
}

it('does not register the log routes by default', function (): void {
    Passport::actingAs(FullStack::user(), [], 'api');

    $this->getJson('api/auth/sso/logs/mine')->assertNotFound();
});

it('lists only the caller\'s own logs on logs/mine', function (): void {
    enableLogRoutes();
    $me = FullStack::user();
    $other = FullStack::user(['pin' => '22222222222222']);
    logFor($me->id, AuthEvent::Login);
    logFor($other->id, AuthEvent::Login);
    Passport::actingAs($me, [], 'api');

    $this->getJson('api/auth/sso/logs/mine')
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.user_id', $me->id)
        ->assertJsonPath('meta.total', 1);
});

it('requires the permission for the admin list', function (): void {
    enableLogRoutes();
    Passport::actingAs(FullStack::user(), [], 'api');

    $this->getJson('api/auth/sso/logs')->assertForbidden();
});

it('filters the admin list by user, event and date', function (): void {
    enableLogRoutes();
    $admin = FullStack::user();
    $other = FullStack::user(['pin' => '22222222222222']);
    Permission::query()->create(['name' => 'sso_logs.list', 'guard_name' => 'api']);
    $admin->givePermissionTo('sso_logs.list');

    logFor($other->id, AuthEvent::Login, '2026-09-01 10:00');
    logFor($other->id, AuthEvent::Lock, '2026-09-02 10:00');
    logFor($other->id, AuthEvent::Login, '2026-09-10 10:00');
    logFor($admin->id, AuthEvent::Login, '2026-09-02 10:00');
    Passport::actingAs($admin, [], 'api');

    $this->getJson('api/auth/sso/logs?user_id='.$other->id.'&event=login&from=2026-09-01&to=2026-09-05')
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.event', 'login')
        ->assertJsonPath('data.0.user.full_name', 'Valiyev Ali');

    $this->getJson('api/auth/sso/logs?event=nope')->assertUnprocessable();
});

it('stores the meta resolver output with each log', function (): void {
    config(['sso.auth_log.meta_resolver' => DeviceMetaResolver::class]);

    app(AuthLogger::class)->record(AuthEvent::Login, 1, request(), null, ['reason' => 'x']);

    expect(SsoAuthLog::query()->first()->meta)->toBe(['device' => 'desktop', 'reason' => 'x']);
});

it('prunes logs older than the retention window, or none when null', function (): void {
    logFor(1, AuthEvent::Login, '-200 days');
    logFor(1, AuthEvent::Login, '-10 days');

    config(['sso.auth_log.retention_days' => null]);
    expect((new SsoAuthLog)->prunable()->count())->toBe(0);

    config(['sso.auth_log.retention_days' => 180]);
    expect((new SsoAuthLog)->prunable()->count())->toBe(1);
});

it('renders /me through the configured me_resource', function (): void {
    config(['sso.me_resource' => ExtendedUserResource::class]);
    Passport::actingAs(FullStack::user(['email' => 'ali@example.test']), [], 'api');

    $this->getJson('api/auth/sso/me')
        ->assertOk()
        ->assertJsonPath('data.user.email', 'ali@example.test')
        ->assertJsonPath('data.user.has_pin', false);
});
