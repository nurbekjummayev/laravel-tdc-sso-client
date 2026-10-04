<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\ClientRepository;

/**
 * Boots everything a real login needs: users (soft-deletable, is_active),
 * Passport tables + in-memory keys + personal access client, and the package
 * tables. Logging is on so denials can be asserted.
 */
final class FullStack
{
    public static function boot(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);

        config([
            'passport.private_key' => $private,
            'passport.public_key' => openssl_pkey_get_details($key)['key'],
            'auth.guards.api' => ['driver' => 'passport', 'provider' => 'users'],
            'auth.providers.users' => ['driver' => 'eloquent', 'model' => GateUser::class],
            'sso.user_model' => GateUser::class,
            'sso.active_column' => 'is_active',
            'sso.auth_log.enabled' => true,
            'sso.cookies.secure' => false,
        ]);

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('pin')->unique();
            $table->string('first_name')->nullable();
            $table->string('last_name')->nullable();
            $table->string('father_name')->nullable();
            $table->string('full_name')->nullable();
            $table->string('tin')->nullable();
            $table->string('email')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
            $table->softDeletes();
        });

        foreach (glob(__DIR__.'/../../vendor/laravel/passport/database/migrations/*.php') ?: [] as $file) {
            (require $file)->up();
        }

        foreach (glob(__DIR__.'/../../database/migrations/*.php') ?: [] as $file) {
            (require $file)->up();
        }

        app(ClientRepository::class)->createPersonalAccessGrantClient('test', 'users');
    }

    public static function user(array $attributes = []): GateUser
    {
        return GateUser::query()->create(array_merge([
            'pin' => '12345678901234',
            'first_name' => 'Ali',
            'last_name' => 'Valiyev',
            'full_name' => 'Valiyev Ali',
        ], $attributes))->refresh();
    }

    /**
     * Prime a valid PKCE state and fake the provider so the callback resolves
     * to the given pin. Returns the request body for POST callback.
     *
     * @return array{code: string, state: string}
     */
    public static function fakeProvider(string $pin = '12345678901234'): array
    {
        Cache::put('sso:state:the-state', 'verifier', 600);

        Http::fake([
            'sso.example.test/oauth/token' => Http::response(['access_token' => 'sso-token']),
            'sso.example.test/oauth/userinfo' => Http::response(['pin' => $pin, 'first_name' => 'Ali']),
        ]);

        return ['code' => 'the-code', 'state' => 'the-state'];
    }
}
