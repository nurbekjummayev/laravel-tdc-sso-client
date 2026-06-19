<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

/**
 * One-shot setup for the SSO session: generate Passport's signing keys and the
 * personal access client used to mint session tokens.
 *
 * Run after the Passport migrations exist (`php artisan migrate`). Idempotent:
 * existing keys are kept unless --force is passed, and the personal access
 * client is created only when one does not already exist.
 */
class InstallSsoCommand extends Command
{
    protected $signature = 'sso:install {--force : Overwrite existing Passport encryption keys}';

    protected $description = 'Generate Passport keys and the personal access client used by the SSO session.';

    public function handle(ClientRepository $clients): int
    {
        if (! Schema::hasTable('oauth_clients')) {
            $this->components->error(
                'The oauth_clients table is missing. Run `php artisan migrate` first '.
                '(publish Passport migrations with `php artisan vendor:publish --tag=passport-migrations`).'
            );

            return self::FAILURE;
        }

        // 1. Passport signing keys.
        $this->call('passport:keys', array_filter([
            '--force' => (bool) $this->option('force'),
        ]));

        // 2. Personal access client (oauth_clients row) — only if absent.
        if ($this->personalAccessClientExists()) {
            $this->components->info('Personal access client already exists — skipping.');

            return self::SUCCESS;
        }

        $client = $clients->createPersonalAccessGrantClient(
            config('app.name', 'Laravel').' SSO Personal Access Client',
            $this->userProvider(),
        );

        $this->components->info("Personal access client created (id: {$client->getKey()}).");

        return self::SUCCESS;
    }

    /**
     * Whether an active personal access client already exists.
     */
    private function personalAccessClientExists(): bool
    {
        return Passport::client()->newQuery()
            ->where('revoked', false)
            ->get()
            ->contains(fn (Client $client): bool => $client->hasGrantType('personal_access'));
    }

    /**
     * The auth user-provider tied to the configured SSO guard, if any.
     */
    private function userProvider(): ?string
    {
        $guard = (string) config('sso.guard', 'api');
        $provider = config("auth.guards.{$guard}.provider");

        return is_string($provider) ? $provider : null;
    }
}
