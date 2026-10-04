<?php

declare(strict_types=1);
use Nurbekjummayev\LaravelTdcSsoClient\Auth\ActiveColumnGate;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoUserResource;

return [

    /*
    |--------------------------------------------------------------------------
    | TDC-SSO Provider Credentials
    |--------------------------------------------------------------------------
    |
    | The OAuth2 (Authorization Code + PKCE) credentials issued by the TDC-SSO
    | provider are read from the host application's `config/services.php` under
    | the `sso` key (services.sso.*):
    |
    |   'sso' => [
    |       'base_url'     => env('SSO_BASE_URL', 'https://apply.epauzb.uz'),
    |       'client_id'    => env('SSO_CLIENT_ID'),
    |       'client_secret'=> env('SSO_CLIENT_SECRET'),
    |       'redirect_uri' => env('SSO_REDIRECT_URI'),
    |       'scope'        => env('SSO_SCOPE', ''),
    |   ],
    |
    | The backend acts as a confidential client (BFF): it performs the
    | server-to-server token exchange and never exposes the SSO token to the
    | browser. It then issues its OWN session to the SPA as httpOnly cookies.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Local User Model
    |--------------------------------------------------------------------------
    |
    | The Eloquent model used to upsert the authenticated SSO subject. It must
    | implement Passport's OAuthenticatable contract (HasApiTokens trait) and
    | expose the columns used by the upsert logic (pin, first_name, last_name,
    | father_name, full_name, tin — each written only when the column exists, so
    | legacy name/username columns are also handled). Expressed as a STRING so the
    | package never imports a concrete application model.
    |
    */

    'user_model' => env('SSO_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | Login Gate
    |--------------------------------------------------------------------------
    |
    | Decides whether a user may hold an SSO session. Checked on callback
    | (before a token is minted), on unlock (before the PIN) and on every
    | authenticated request through the `sso.active` middleware. A rejected user
    | loses all Passport + unlock tokens and gets a 403 with
    | `code: account_inactive`. Soft-deleted users are always rejected.
    |
    | `login_gate` is a class-string implementing
    | Nurbekjummayev\LaravelTdcSsoClient\Contracts\LoginGate (a class, not a
    | closure, so `config:cache` keeps working). The default gate allows the
    | user when `active_column` is truthy; a null column disables the check.
    |
    */

    'login_gate' => ActiveColumnGate::class,

    'active_column' => env('SSO_ACTIVE_COLUMN'),

    /*
    |--------------------------------------------------------------------------
    | User Resource
    |--------------------------------------------------------------------------
    |
    | JsonResource used for the `user` payload of callback, unlock and me.
    | Extend Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoUserResource
    | to add host fields (email, photo, ...) while keeping has_pin/permissions.
    |
    */

    'me_resource' => SsoUserResource::class,

    /*
    |--------------------------------------------------------------------------
    | Passport Token Name
    |--------------------------------------------------------------------------
    */

    'token_name' => env('SSO_TOKEN_NAME', 'spa'),

    /*
    |--------------------------------------------------------------------------
    | Session (Access) Token TTL
    |--------------------------------------------------------------------------
    |
    | Lifetime (minutes) of the Passport personal access token minted as the
    | working "session" token. It is short-lived: it dies on screen lock and is
    | re-minted on unlock. The session cookie shares this lifetime.
    |
    */

    'token_expiry_minutes' => (int) env('SSO_TOKEN_EXPIRY_MINUTES', 60),

    /*
    |--------------------------------------------------------------------------
    | Unlock Token TTL (absolute session cap)
    |--------------------------------------------------------------------------
    |
    | Lifetime (minutes) of the long-lived "unlock" token used together with the
    | PIN to re-mint a session token after a screen lock. This is a HARD ceiling
    | measured from login: rotations never extend it. Default 720 = 12 hours.
    |
    */

    'unlock_token_ttl_minutes' => (int) env('SSO_UNLOCK_TOKEN_TTL', 720),

    /*
    |--------------------------------------------------------------------------
    | PKCE State Cache TTL (seconds)
    |--------------------------------------------------------------------------
    */

    'state_ttl' => (int) env('SSO_STATE_TTL', 600),

    /*
    |--------------------------------------------------------------------------
    | Session Cookies
    |--------------------------------------------------------------------------
    |
    | The session and unlock tokens are delivered to the SPA as httpOnly cookies
    | so JavaScript can never read them (XSS protection). `same_site=strict`
    | gives CSRF protection when the SPA and API share a site (e.g.
    | admin.td.uz / api.td.uz). For cross-site setups use 'none' + Secure and
    | configure CORS credentials.
    |
    */

    'cookies' => [
        'session_name' => env('SSO_SESSION_COOKIE', 'session_token'),
        'unlock_name' => env('SSO_UNLOCK_COOKIE', 'unlock_token'),
        'domain' => env('SSO_COOKIE_DOMAIN'),
        'secure' => (bool) env('SSO_COOKIE_SECURE', true),
        'same_site' => env('SSO_COOKIE_SAMESITE', 'strict'),
    ],

    /*
    |--------------------------------------------------------------------------
    | PIN
    |--------------------------------------------------------------------------
    |
    | The screen-lock PIN. Stored hashed in the `sso_lock_pins` table (never on
    | the users table). `max_attempts` failed unlocks lock the PIN for
    | `lockout_minutes`, after which a full SSO re-login is required.
    |
    */

    'pin' => [
        // The PIN is a 4-digit numeric code by default.
        'min_length' => (int) env('SSO_PIN_MIN_LENGTH', 4),
        'max_length' => (int) env('SSO_PIN_MAX_LENGTH', 4),
        'max_attempts' => (int) env('SSO_PIN_MAX_ATTEMPTS', 5),
        'lockout_minutes' => (int) env('SSO_PIN_LOCKOUT_MINUTES', 15),
    ],

    /*
    |--------------------------------------------------------------------------
    | Idle Timeout (server-side backstop)
    |--------------------------------------------------------------------------
    |
    | The screen lock is triggered by the frontend in real time. As a backstop,
    | the backend revokes the session token if no request arrives within
    | `timeout` minutes, so a bypassed frontend lock cannot keep the token alive.
    |
    */

    'idle' => [
        'enabled' => (bool) env('SSO_IDLE_ENABLED', true),
        'timeout' => (int) env('SSO_IDLE_TIMEOUT', 15),
    ],

    /*
    |--------------------------------------------------------------------------
    | Route Registration
    |--------------------------------------------------------------------------
    */

    'routes' => [
        'enabled' => true,
        'prefix' => env('SSO_ROUTE_PREFIX', 'api/auth/sso'),
        'middleware' => ['api'],

        /*
        | Middleware guarding the authenticated endpoints (me, lock, set-pin,
        | logout). The session cookie is injected as a Bearer token before this
        | runs. Uses the Passport `api` guard by default.
        */
        'auth_middleware' => env('SSO_AUTH_MIDDLEWARE', 'auth:api'),

        /*
        | Read endpoints over sso_auth_logs (both off by default):
        |   mine  -> GET logs/mine, the caller's own history
        |   admin -> GET logs, every user, behind `sso.auth_log.permission`
        */
        'logs' => [
            'mine' => (bool) env('SSO_LOGS_MINE_ENABLED', false),
            'admin' => (bool) env('SSO_LOGS_ADMIN_ENABLED', false),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authorization Guard
    |--------------------------------------------------------------------------
    */

    'guard' => env('SSO_GUARD', 'api'),

    /*
    |--------------------------------------------------------------------------
    | Role Synchronisation
    |--------------------------------------------------------------------------
    |
    | When enabled, roles present in the SSO userinfo payload are synced onto the
    | local user via spatie/laravel-permission. Only roles that already exist on
    | the configured guard are assigned.
    |
    */

    'sync_roles' => (bool) env('SSO_SYNC_ROLES', false),

    /*
    |--------------------------------------------------------------------------
    | Automatic User Provisioning
    |--------------------------------------------------------------------------
    |
    |   true  -> a new local user is created on first login.
    |   false -> login is rejected with a 403 for unknown users (safe DEFAULT).
    |
    */

    'auto_create_user' => (bool) env('SSO_AUTO_CREATE_USER', false),

    /*
    |--------------------------------------------------------------------------
    | Default Roles For Newly Provisioned Users
    |--------------------------------------------------------------------------
    |
    | @var array<int, string>
    */

    'default_roles' => array_values(array_filter(
        explode(',', (string) env('SSO_DEFAULT_ROLES', '')),
        static fn (string $role): bool => trim($role) !== '',
    )),

    /*
    |--------------------------------------------------------------------------
    | Default Permissions For Newly Provisioned Users
    |--------------------------------------------------------------------------
    |
    | @var array<int, string>
    */

    'default_permissions' => array_values(array_filter(
        explode(',', (string) env('SSO_DEFAULT_PERMISSIONS', '')),
        static fn (string $permission): bool => trim($permission) !== '',
    )),

    /*
    |--------------------------------------------------------------------------
    | Authentication Logging
    |--------------------------------------------------------------------------
    |
    | Persist auth events (login, logout, lock, unlock, pin_set, pin_changed,
    | login_denied) to the `sso_auth_logs` table with the IP address and user
    | agent.
    |
    | meta_resolver   class-string implementing
    |                 Nurbekjummayev\LaravelTdcSsoClient\Contracts\AuthLogMetaResolver;
    |                 its array is stored in the `meta` json column.
    | retention_days  rows older than this are removed by `model:prune`
    |                 (schedule it with --model for SsoAuthLog); null keeps all.
    | permission      required by the admin `GET logs` endpoint.
    |
    */

    'auth_log' => [
        'enabled' => (bool) env('SSO_AUTH_LOG_ENABLED', true),
        'meta_resolver' => null,
        'retention_days' => env('SSO_AUTH_LOG_RETENTION_DAYS', 180),
        'permission' => env('SSO_AUTH_LOG_PERMISSION', 'sso_logs.list'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Outbound HTTP Timeouts (seconds)
    |--------------------------------------------------------------------------
    */

    'http' => [
        'timeout' => (int) env('SSO_HTTP_TIMEOUT', 10),
        'connect_timeout' => (int) env('SSO_HTTP_CONNECT_TIMEOUT', 5),
    ],

];
