<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\PersonalAccessTokenResult;
use Nurbekjummayev\LaravelTdcSsoClient\Contracts\LoginGate;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidPinException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidUnlockTokenException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\LoginDeniedException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\PinLockedException;
use Nurbekjummayev\LaravelTdcSsoClient\Support\CurrentToken;
use RuntimeException;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

/**
 * Orchestrates the cookie-based SSO session on top of {@see SsoClient}.
 *
 * The login flow mints two credentials: a short-lived Passport "session" token
 * (the working access token, killed on screen lock) and a long-lived "unlock"
 * token (used with the PIN to re-mint a session token). Both are returned as
 * raw strings; the controller is responsible for placing them in httpOnly
 * cookies.
 */
class SsoService
{
    public function __construct(
        private readonly SsoClient $ssoClient,
        private readonly AuthLogger $authLogger,
        private readonly UnlockTokenManager $unlockTokens,
        private readonly PinManager $pins,
        private readonly LoginGate $gate,
    ) {}

    /**
     * Begin the SSO flow: create state + PKCE verifier, cache them, and return
     * the provider authorize URL the browser must be redirected to.
     */
    public function buildRedirect(): string
    {
        $state = Str::random(40);
        $codeVerifier = $this->ssoClient->generateCodeVerifier();

        Cache::put($this->stateKey($state), $codeVerifier, $this->stateTtl());

        return $this->ssoClient->buildAuthorizeUrl(
            $state,
            $this->ssoClient->codeChallenge($codeVerifier),
        );
    }

    /**
     * Handle the provider callback: validate state, exchange the code, fetch
     * userinfo, upsert the user, and mint the session + unlock tokens.
     *
     * @return array{user: Model, session_token: string, unlock_token: string}
     *
     * @throws RuntimeException when the state is invalid or userinfo lacks a pin
     * @throws LoginDeniedException when the user is unknown (and auto-provisioning
     *                              is disabled), soft-deleted, or rejected by the gate
     */
    public function handleCallback(string $code, string $state, ?Request $request = null): array
    {
        $codeVerifier = Cache::pull($this->stateKey($state));

        if (! is_string($codeVerifier) || $codeVerifier === '') {
            throw new RuntimeException('Invalid or expired SSO state.');
        }

        $tokenData = $this->ssoClient->exchangeCode($code, $codeVerifier);

        // /oauth/userinfo is one-shot: call it immediately and persist.
        $userInfo = $this->ssoClient->fetchUserInfo($tokenData['access_token']);
        $pin = isset($userInfo['pin']) ? (string) $userInfo['pin'] : '';

        if ($pin === '') {
            throw new RuntimeException('SSO userinfo did not include a pin.');
        }

        $user = $this->upsertUser($pin, $userInfo, $request);

        $this->ensureCanLogin($user, $request);

        $sessionToken = $this->mintSessionToken($user, $request);
        $unlockToken = $this->unlockTokens->issue((int) $user->getKey());

        return [
            'user' => $user,
            'session_token' => $sessionToken,
            'unlock_token' => $unlockToken,
        ];
    }

    /**
     * Unlock the session: validate the unlock token + PIN and mint a fresh
     * session token, rotating the unlock token.
     *
     * @return array{user: Model, session_token: string, unlock_token: string}
     *
     * @throws InvalidUnlockTokenException
     * @throws InvalidPinException
     * @throws PinLockedException
     * @throws LoginDeniedException when the user is gone or rejected by the gate
     */
    public function unlock(string $unlockToken, string $pin, ?Request $request = null): array
    {
        // Identify the user from the unlock token first (the session token is
        // dead during lock, so the request is not otherwise authenticated). The
        // token is validated but NOT yet rotated.
        $unlockRecord = $this->unlockTokens->verify($unlockToken);
        $userId = (int) $unlockRecord->user_id;

        // Gate BEFORE the PIN: a blocked user must not burn PIN attempts or learn
        // anything from them, and their unlock chain is killed on the spot.
        $user = $this->findUser($userId);

        if ($user === null) {
            $this->unlockTokens->revokeAllForUser($userId);
            $this->recordDenied($userId, LoginDeniedException::INACTIVE, $request);

            throw LoginDeniedException::inactive();
        }

        $this->ensureCanLogin($user, $request);

        // Verify the PIN. A wrong PIN throws here and the unlock token is left
        // intact, so the SPA can retry with the same cookie.
        $this->pins->verify($userId, $pin);

        // PIN ok — now rotate the unlock token and mint a fresh session.
        $newUnlockToken = $this->unlockTokens->rotate($unlockRecord);

        $sessionToken = $this->mintSessionToken($user, $request, AuthEvent::Unlock);

        return [
            'user' => $user,
            'session_token' => $sessionToken,
            'unlock_token' => $newUnlockToken,
        ];
    }

    /**
     * Screen lock: revoke the caller's current session token. The unlock token
     * is intentionally left alive so the PIN can re-mint a session.
     */
    public function lock(Model $user, ?Request $request = null): void
    {
        $tokenId = $this->revokeCurrentSessionToken($user);

        $this->authLogger->record(AuthEvent::Lock, (int) $user->getKey(), $request, $tokenId);
    }

    /**
     * Full logout: revoke the session token AND all unlock tokens.
     */
    public function logout(Model $user, ?Request $request = null): void
    {
        $tokenId = $this->revokeCurrentSessionToken($user);

        $this->unlockTokens->revokeAllForUser((int) $user->getKey());

        $this->authLogger->record(AuthEvent::Logout, (int) $user->getKey(), $request, $tokenId);
    }

    /**
     * Whether the user may hold an SSO session: not soft-deleted and allowed by
     * the configured {@see LoginGate}.
     */
    public function canLogin(Model $user): bool
    {
        if (method_exists($user, 'trashed') && $user->trashed()) {
            return false;
        }

        return $this->gate->allows($user);
    }

    /**
     * Throw (after revoking every credential and logging) when the user may not
     * hold an SSO session.
     *
     * @throws LoginDeniedException
     */
    public function ensureCanLogin(Model $user, ?Request $request = null): void
    {
        if ($this->canLogin($user)) {
            return;
        }

        $this->revokeAll($user);
        $this->recordDenied((int) $user->getKey(), LoginDeniedException::INACTIVE, $request);

        throw LoginDeniedException::inactive();
    }

    /**
     * Revoke every credential the user holds: Passport access tokens and unlock
     * tokens. Call it when a user is deactivated or deleted.
     *
     * @param  bool  $onlySso  limit Passport revocation to tokens named
     *                         `sso.token_name`, keeping integration tokens alive
     */
    public function revokeAll(Model $user, bool $onlySso = false): void
    {
        if (method_exists($user, 'tokens')) {
            $user->tokens()
                ->where('revoked', false)
                ->when($onlySso, fn (Builder $query) => $query->where('name', $this->tokenName()))
                ->update(['revoked' => true]);
        }

        $this->unlockTokens->revokeAllForUser((int) $user->getKey());
    }

    /**
     * Resolve a user by primary key using the configured model.
     */
    public function resolveUser(int $userId): Model
    {
        $modelClass = $this->userModel();

        /** @var Model $user */
        $user = $modelClass::query()->findOrFail($userId);

        return $user;
    }

    /**
     * Find a user by primary key, including soft-deleted ones so they can be
     * rejected explicitly instead of surfacing as a 404.
     */
    private function findUser(int $userId): ?Model
    {
        /** @var Model|null $user */
        $user = $this->userQuery()->find($userId);

        return $user;
    }

    private function recordDenied(?int $userId, string $reason, ?Request $request): void
    {
        $this->authLogger->record(AuthEvent::LoginDenied, $userId, $request, null, ['reason' => $reason]);
    }

    /**
     * Mint a backend Passport session token for the user and log the event.
     */
    private function mintSessionToken(Model $user, ?Request $request, AuthEvent $event = AuthEvent::Login): string
    {
        if (! $user instanceof OAuthenticatable) {
            throw new RuntimeException(
                'The configured SSO user model must implement '.OAuthenticatable::class.
                ' (use Laravel Passport\'s HasApiTokens trait).'
            );
        }

        /** @var PersonalAccessTokenResult $tokenResult */
        $tokenResult = $user->createToken($this->tokenName());

        $this->authLogger->record(
            $event,
            (int) $user->getKey(),
            $request,
            (string) $tokenResult->accessTokenId,
        );

        return $tokenResult->accessToken;
    }

    /**
     * Revoke the Passport access token the current request authenticated with.
     */
    private function revokeCurrentSessionToken(Model $user): ?string
    {
        $token = CurrentToken::of($user);

        CurrentToken::revoke($token);

        return CurrentToken::id($token);
    }

    /**
     * Create or update the local user keyed by the SSO pin (PINFL identifier).
     *
     * The SSO payload maps to the identity columns first_name, last_name,
     * father_name, full_name and tin. Because the package works against a
     * host-configured model, each attribute is written ONLY when the users table
     * actually has that column — so the same package fits schemas that use, say,
     * tin vs none, or the legacy name/username columns.
     *
     * Soft-deleted users are looked up too and rejected: otherwise
     * `firstOrNew` would miss them and, with auto-provisioning on, re-create the
     * account (or hit the unique pin index).
     *
     * @param  array<string, mixed>  $userInfo
     *
     * @throws LoginDeniedException when the user is unknown (and auto-provisioning is disabled) or soft-deleted
     */
    private function upsertUser(string $pin, array $userInfo, ?Request $request): Model
    {
        $user = $this->userQuery()->firstOrNew(['pin' => $pin]);

        $isNewUser = ! $user->exists;

        if ($isNewUser && ! (bool) config('sso.auto_create_user', false)) {
            $this->recordDenied(null, LoginDeniedException::NOT_REGISTERED, $request);

            throw LoginDeniedException::notRegistered();
        }

        if (method_exists($user, 'trashed') && $user->trashed()) {
            $this->ensureCanLogin($user, $request);
        }

        $columns = $this->userColumns($user);

        $firstName = $this->stringField($userInfo, 'first_name');
        $lastName = $this->stringField($userInfo, 'last_name');
        $fatherName = $this->stringField($userInfo, 'father_name');
        $fullName = $this->stringField($userInfo, 'full_name')
            ?? $this->composeFullName($lastName, $firstName, $fatherName);

        $identity = [
            'first_name' => $firstName,
            'last_name' => $lastName,
            'father_name' => $fatherName,
            'full_name' => $fullName,
            'tin' => $this->stringField($userInfo, 'tin'),
        ];

        foreach ($identity as $column => $value) {
            if (in_array($column, $columns, true)) {
                $user->setAttribute($column, $value);
            }
        }

        // Legacy fallbacks for apps whose users table still uses name/username.
        if (in_array('name', $columns, true) && blank($user->getAttribute('name'))) {
            $user->setAttribute('name', $fullName ?? $pin);
        }

        if (in_array('username', $columns, true) && blank($user->getAttribute('username'))) {
            $user->setAttribute('username', $pin);
        }

        $user->save();

        // Default roles/permissions are applied ONLY to freshly provisioned users.
        if ($isNewUser) {
            // Load DB defaults (e.g. is_active) so the login gate sees them.
            $user->refresh();

            $this->assignDefaultRolesAndPermissions($user);
        }

        $this->syncRoles($user, $userInfo);

        return $user;
    }

    /**
     * The column names of the configured user model's table.
     *
     * @return array<int, string>
     */
    private function userColumns(Model $user): array
    {
        return $user->getConnection()
            ->getSchemaBuilder()
            ->getColumnListing($user->getTable());
    }

    /**
     * Read a string field from the SSO payload, or null when absent/empty.
     *
     * @param  array<string, mixed>  $userInfo
     */
    private function stringField(array $userInfo, string $key): ?string
    {
        return isset($userInfo[$key]) && $userInfo[$key] !== ''
            ? (string) $userInfo[$key]
            : null;
    }

    /**
     * Build a display name from the parts when the payload omits full_name, so a
     * NOT NULL full_name column is still satisfied.
     */
    private function composeFullName(?string $lastName, ?string $firstName, ?string $fatherName): ?string
    {
        $parts = array_filter([$lastName, $firstName, $fatherName], static fn (?string $p): bool => $p !== null && $p !== '');

        return $parts === [] ? null : implode(' ', $parts);
    }

    /**
     * Grant the configured default roles and permissions to a brand-new user.
     */
    private function assignDefaultRolesAndPermissions(Model $user): void
    {
        $guard = (string) config('sso.guard', 'api');

        /** @var array<int, string> $defaultRoles */
        $defaultRoles = (array) config('sso.default_roles', []);

        /** @var array<int, string> $defaultPermissions */
        $defaultPermissions = (array) config('sso.default_permissions', []);

        if ($defaultRoles !== [] && method_exists($user, 'assignRole')) {
            /** @var class-string<Role> $roleModel */
            $roleModel = config('permission.models.role', Role::class);

            $existingRoles = $roleModel::query()
                ->where('guard_name', $guard)
                ->whereIn('name', $defaultRoles)
                ->pluck('name')
                ->all();

            $missingRoles = array_diff($defaultRoles, $existingRoles);

            if ($missingRoles !== []) {
                Log::warning('SSO default roles skipped (not found on guard).', [
                    'guard' => $guard,
                    'roles' => array_values($missingRoles),
                ]);
            }

            if ($existingRoles !== []) {
                $user->assignRole($existingRoles);
            }
        }

        if ($defaultPermissions !== [] && method_exists($user, 'givePermissionTo')) {
            /** @var class-string<Permission> $permissionModel */
            $permissionModel = config('permission.models.permission', Permission::class);

            $existingPermissions = $permissionModel::query()
                ->where('guard_name', $guard)
                ->whereIn('name', $defaultPermissions)
                ->pluck('name')
                ->all();

            $missingPermissions = array_diff($defaultPermissions, $existingPermissions);

            if ($missingPermissions !== []) {
                Log::warning('SSO default permissions skipped (not found on guard).', [
                    'guard' => $guard,
                    'permissions' => array_values($missingPermissions),
                ]);
            }

            if ($existingPermissions !== []) {
                $user->givePermissionTo($existingPermissions);
            }
        }
    }

    /**
     * Sync the user's spatie roles from the SSO payload, when enabled.
     *
     * @param  array<string, mixed>  $userInfo
     */
    private function syncRoles(Model $user, array $userInfo): void
    {
        if (! (bool) config('sso.sync_roles', false)) {
            return;
        }

        if (! method_exists($user, 'syncRoles')) {
            return;
        }

        $roles = [];

        if (isset($userInfo['role']) && is_string($userInfo['role'])) {
            $roles[] = $userInfo['role'];
        }

        if (isset($userInfo['roles']) && is_array($userInfo['roles'])) {
            foreach ($userInfo['roles'] as $role) {
                if (is_string($role)) {
                    $roles[] = $role;
                }
            }
        }

        $roles = array_values(array_unique(array_filter($roles)));

        if ($roles === []) {
            return;
        }

        $guard = (string) config('sso.guard', 'api');

        /** @var class-string<Role> $roleModel */
        $roleModel = config('permission.models.role', Role::class);

        $existing = $roleModel::query()
            ->where('guard_name', $guard)
            ->whereIn('name', $roles)
            ->pluck('name')
            ->all();

        if ($existing === []) {
            return;
        }

        $user->syncRoles($existing);
    }

    private function stateKey(string $state): string
    {
        return 'sso:state:'.$state;
    }

    private function stateTtl(): int
    {
        return (int) config('sso.state_ttl', 600);
    }

    private function tokenName(): string
    {
        return (string) config('sso.token_name', 'spa');
    }

    /**
     * A query on the configured user model that also sees soft-deleted rows.
     *
     * @return Builder<Model>
     */
    private function userQuery(): Builder
    {
        $modelClass = $this->userModel();

        if (in_array(SoftDeletes::class, class_uses_recursive($modelClass), true)) {
            /** @phpstan-ignore-next-line staticMethod.notFound */
            return $modelClass::withTrashed();
        }

        return $modelClass::query();
    }

    /**
     * @return class-string<Model>
     */
    private function userModel(): string
    {
        /** @var class-string<Model> $model */
        $model = (string) config('sso.user_model', User::class);

        return $model;
    }
}
