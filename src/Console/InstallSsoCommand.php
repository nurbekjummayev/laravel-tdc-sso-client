<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

/**
 * One-shot setup for the SSO session, in dependency order:
 *   1. publish Passport's migration files (the package does not bundle oauth_*)
 *   2. run migrations (creates oauth_* + the package's own tables)
 *   3. generate Passport's signing keys
 *   4. create the personal access client used to mint session tokens
 *
 * Idempotent: published migrations and existing keys are kept unless --force is
 * passed, and the personal access client is created only when one is absent.
 * `migrate` prompts before running in production unless --force is given, so
 * pass --force in non-interactive (CI/deploy) contexts.
 */
class InstallSsoCommand extends Command
{
    protected $signature = 'sso:install {--force : Overwrite published migrations & keys and run migrate non-interactively}';

    protected $description = 'Install the SSO backend: publish Passport migrations, migrate, generate keys, and create the personal access client.';

    public function handle(ClientRepository $clients): int
    {
        $force = (bool) $this->option('force');

        // 1. Publish Passport's migration files (skips existing unless --force).
        $this->call('vendor:publish', array_filter([
            '--tag' => 'passport-migrations',
            '--force' => $force,
        ]));

        // 2. Create the schema: oauth_* (just published) + the package's tables.
        $this->call('migrate', array_filter([
            '--force' => $force,
        ]));

        // The personal access client needs oauth_clients to exist by now.
        if (! Schema::hasTable('oauth_clients')) {
            $this->components->error(
                'oauth_clients is still missing after migrate. Check that the Passport '.
                'migrations were published and that the migration ran successfully.'
            );

            return self::FAILURE;
        }

        // 3. Passport signing keys.
        $this->call('passport:keys', array_filter([
            '--force' => $force,
        ]));

        // 4. Personal access client (oauth_clients row) — only if absent.
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
