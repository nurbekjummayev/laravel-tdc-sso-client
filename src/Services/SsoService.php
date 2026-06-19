<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\PersonalAccessTokenResult;
use NurbekJummayev\ApiResponseHelper\Exceptions\ForbiddenException;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidPinException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidUnlockTokenException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\PinLockedException;
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
     * @throws RuntimeException when the state is invalid or userinfo lacks a pinfl
     * @throws ForbiddenException when the user is unknown and auto-provisioning is disabled
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
        $pinfl = isset($userInfo['pinfl']) ? (string) $userInfo['pinfl'] : '';

        if ($pinfl === '') {
            throw new RuntimeException('SSO userinfo did not include a pinfl.');
        }

        $user = $this->upsertUser($pinfl, $userInfo);

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
     */
    public function unlock(string $unlockToken, string $pin, ?Request $request = null): array
    {
        // Identify the user from the unlock token first (the session token is
        // dead during lock, so the request is not otherwise authenticated). The
        // token is validated but NOT yet rotated.
        $unlockRecord = $this->unlockTokens->verify($unlockToken);
        $userId = (int) $unlockRecord->user_id;

        // Verify the PIN. A wrong PIN throws here and the unlock token is left
        // intact, so the SPA can retry with the same cookie.
        $this->pins->verify($userId, $pin);

        // PIN ok — now rotate the unlock token and mint a fresh session.
        $newUnlockToken = $this->unlockTokens->rotate($unlockRecord);

        $user = $this->resolveUser($userId);

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
        if (! method_exists($user, 'token')) {
            return null;
        }

        $token = $user->token();

        if ($token === null) {
            return null;
        }

        $tokenId = (string) $token->getKey();

        $token->revoke();

        return $tokenId;
    }

    /**
     * Create or update the local user keyed by the SSO pinfl.
     *
     * @param  array<string, mixed>  $userInfo
     *
     * @throws ForbiddenException when the user is unknown and auto-provisioning is disabled
     */
    private function upsertUser(string $pinfl, array $userInfo): Model
    {
        $fullName = isset($userInfo['full_name']) ? (string) $userInfo['full_name'] : null;
        $stir = isset($userInfo['stir']) ? (string) $userInfo['stir'] : null;

        $modelClass = $this->userModel();

        $user = $modelClass::query()->firstOrNew(['pinfl' => $pinfl]);

        $isNewUser = ! $user->exists;

        if ($isNewUser && ! (bool) config('sso.auto_create_user', false)) {
            throw new ForbiddenException('Foydalanuvchi tizimda ro\'yxatdan o\'tmagan.');
        }

        $user->setAttribute('full_name', $fullName);
        $user->setAttribute('stir', $stir);

        // name is NOT NULL; fall back to the full name or the pinfl.
        if (blank($user->getAttribute('name'))) {
            $user->setAttribute('name', $fullName ?? $pinfl);
        }

        // username is unique; fall back to the pinfl for SSO-only users.
        if (blank($user->getAttribute('username'))) {
            $user->setAttribute('username', $pinfl);
        }

        $user->save();

        // Default roles/permissions are applied ONLY to freshly provisioned users.
        if ($isNewUser) {
            $this->assignDefaultRolesAndPermissions($user);
        }

        $this->syncRoles($user, $userInfo);

        return $user;
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
     * @return class-string<Model>
     */
    private function userModel(): string
    {
        /** @var class-string<Model> $model */
        $model = (string) config('sso.user_model', User::class);

        return $model;
    }
}
