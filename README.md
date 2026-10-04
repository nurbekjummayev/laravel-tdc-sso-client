# Laravel TDC-SSO Client

[![Tests](https://github.com/nurbekjummayev/laravel-tdc-sso-client/actions/workflows/tests.yml/badge.svg)](https://github.com/nurbekjummayev/laravel-tdc-sso-client/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A Laravel package implementing **TDC-SSO** login over OAuth2 (Authorization
Code + PKCE) using the **Backend-for-Frontend (BFF)** pattern, with a
**cookie-based session, screen-lock, and PIN unlock** flow.

The backend performs the server-to-server token exchange and never exposes the
SSO provider token to the browser. It issues its own session to the SPA as two
**httpOnly cookies** — neither is readable by JavaScript:

- **`session_token`** — the short-lived working access token (a Passport
  personal access token). Killed on screen lock.
- **`unlock_token`** — a long-lived token (12h hard cap) used together with the
  user's PIN to re-mint a session token after a lock, without a full re-login.

## Requirements

- PHP 8.2+ · Laravel 12/13
- [laravel/passport](https://laravel.com/docs/passport) (user model must implement `OAuthenticatable` / use `HasApiTokens`)
- [spatie/laravel-permission](https://spatie.be/docs/laravel-permission)

## Installation

```bash
composer require nurbekjummayev/laravel-tdc-sso-client

# (optional) publish the package config to customise it:
php artisan vendor:publish --tag=tdc-sso-client-config

# One command does the rest — publishes Passport's migrations, runs migrate,
# generates Passport keys, and creates the personal access client (idempotent):
php artisan sso:install
```

In production / non-interactive (CI, deploy) contexts, pass `--force` so the
embedded `migrate` runs without the confirmation prompt:
`php artisan sso:install --force`.

> **Migrations.** The package ships only its OWN tables: `sso_auth_logs`,
> `sso_lock_pins`, `sso_unlock_tokens`. The Passport `oauth_*` tables are
> Passport's own schema — `sso:install` publishes them
> (`vendor:publish --tag=passport-migrations`) and runs `migrate` for you. The
> bundled spatie/permission migration is guarded with `Schema::hasTable(...)`, so
> it is skipped if the host app already installed it.

## Token & lock model

```
Login (SSO) ─▶ callback ─▶ Set-Cookie: session_token (short)  +  unlock_token (12h)
                           Body: { user }  (tokens are NEVER in the body)

Working      ─▶ browser auto-sends session_token cookie; a middleware copies it
                into the Authorization header so auth:api authenticates.

Lock (idle)  ─▶ frontend locks the screen in real time, calls POST /lock
                ─▶ session_token revoked + cookie cleared (unlock_token kept)

Unlock (PIN) ─▶ POST /unlock  (unlock_token cookie + PIN)
                ─▶ PIN verified, unlock_token rotated, new session_token issued

12h cap / wrong-token / idle backstop ─▶ full SSO re-login
```

The screen-lock **trigger** is the frontend's job (real-time input-activity
detection). The backend enforces a server-side **idle backstop**: if no request
arrives within `sso.idle.timeout` minutes, the session token is revoked.

## Routes

Registered under the `api/auth/sso` prefix (configurable via `sso.routes.prefix`):

| Method | URI | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `redirect` | public | Redirect to the SSO authorize endpoint |
| `POST` | `callback` | public | Exchange `code`+`state`, set session + unlock cookies |
| `POST` | `unlock` | unlock cookie + PIN | Re-mint a session token after a lock |
| `GET` | `me` | session cookie | Current user (includes `has_pin`) |
| `POST` | `set-pin` | session cookie | Set/change the PIN — body `pin` + `pin_confirmation` (+ `current_pin` to change) |
| `POST` | `lock` | session cookie | Revoke the session token, clear its cookie |
| `POST` | `logout` | session cookie | Revoke session + unlock tokens, clear both cookies |
| `GET` | `logs/mine` | session cookie | Caller's own auth history (off by default, `SSO_LOGS_MINE_ENABLED`) |
| `GET` | `logs` | session cookie + `sso_logs.list` | Every user's auth history (off by default, `SSO_LOGS_ADMIN_ENABLED`) |

The authenticated routes run behind: cookie→Bearer injection → `auth:api` →
login gate (`sso.active`) → idle backstop. `unlock` is intentionally public (the session token
is dead during a lock) and is gated by the unlock cookie + PIN.

The `/me` response carries `has_pin` so the SPA knows whether to show the
**set-PIN** screen or the **unlock** screen — no separate `check-pin` call.

### User response format

The `callback`, `me`, and `unlock` endpoints return a `user` object:

```json
{
  "user": {
    "id": 1,
    "first_name": "Nurbek",
    "last_name": "Jummayev",
    "father_name": "Abdullayevich",
    "full_name": "Jummayev Nurbek Abdullayevich",
    "pin": "12345678901234",
    "tin": "123456789",
    "created_at": "2026-06-23T10:00:00.000000Z",
    "updated_at": "2026-06-23T10:00:00.000000Z",
    "role": "admin",
    "permissions": ["users.view", "users.edit"],
    "has_pin": true
  }
}
```

| Field | Type | Description |
| --- | --- | --- |
| `id` | int | User ID |
| `first_name` | string | First name |
| `last_name` | string | Last name |
| `father_name` | string\|null | Father's name (nullable) |
| `full_name` | string | Full name |
| `pin` | string | PINFL (14 digits) |
| `tin` | string\|null | TIN (9 digits, nullable) |
| `created_at` | datetime | Created timestamp |
| `updated_at` | datetime | Updated timestamp |
| `role` | string\|null | First spatie role name |
| `permissions` | array | All spatie permission names |
| `has_pin` | bool | Whether a screen-lock PIN is set |

Customise the payload with `sso.me_resource` — extend `SsoUserResource` and
keep `has_pin` / `permissions` from the parent:

```php
use Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoUserResource;

class MeResource extends SsoUserResource
{
    public function toArray(Request $request): array
    {
        $this->resource->loadMissing('photo');

        return [
            ...parent::toArray($request),
            'email' => $this->resource->email,
            'photo' => $this->resource->photo?->url,
        ];
    }
}
```

## Login gate (inactive / deleted users)

Set `SSO_ACTIVE_COLUMN=is_active` and a user whose column is falsy cannot hold
a session. The gate runs:

- on **callback** — after the upsert, before any token is minted;
- on **unlock** — before the PIN is checked (no PIN attempts are burned);
- on **every authenticated request** — through the `sso.active` middleware.

A rejected user loses every Passport and unlock token, both cookies are
cleared, an `login_denied` event is logged, and the response is a 403 with a
machine-readable code:

```json
{ "msg": "...", "success": false, "data": null, "code": "account_inactive" }
```

`code` is `account_inactive` (gate / soft-deleted) or `account_not_registered`
(unknown user with `auto_create_user=false`). Soft-deleted users are always
rejected and never re-created.

Add the middleware to your own API routes, after `auth:api`:

```php
Route::middleware(['auth:api', 'sso.active'])->group(...);
```

For a custom rule, bind a class implementing
`Nurbekjummayev\LaravelTdcSsoClient\Contracts\LoginGate` in `sso.login_gate`
(a class, not a closure, so `config:cache` keeps working).

When you deactivate or delete a user, kill their sessions immediately:

```php
app(SsoService::class)->revokeAll($user);                 // all Passport + unlock tokens
app(SsoService::class)->revokeAll($user, onlySso: true);  // keep non-SSO tokens
```

## Auth logs

Every event (`login`, `logout`, `lock`, `unlock`, `pin_set`, `pin_changed`,
`login_denied`) is stored in `sso_auth_logs` with IP, user agent and a `meta`
json column. To fill `meta` (geolocation, device, ...), set
`sso.auth_log.meta_resolver` to a class implementing `AuthLogMetaResolver`.

`GET logs` (admin) and `GET logs/mine` accept `event` (string or array),
`from` / `to` (dates, inclusive), `per_page` (max 100) and — admin only —
`user_id`. Results are paginated, newest first.

Rows older than `sso.auth_log.retention_days` (default 180, `null` = keep all)
are pruned by `model:prune`. Laravel only discovers models under `app/`, so
schedule it explicitly:

```php
Schedule::command('model:prune', [
    '--model' => [\Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog::class],
])->daily();
```

## PIN

The screen-lock PIN lives in its own `sso_lock_pins` table (never on the users
table): a bcrypt hash, when it was set/changed (`created_at` / `updated_at`),
the last IP / user agent of that set/change, and a failed-attempt counter with
lockout. PIN set/change events are also written to `sso_auth_logs`.

Setting or changing a PIN requires `pin` **and** `pin_confirmation` (they must
match); changing an existing PIN additionally requires the correct
`current_pin`. After `sso.pin.max_attempts` failed unlocks the PIN locks for
`sso.pin.lockout_minutes`.

## Configuration

Provider credentials live in `config/services.php`:

```php
'sso' => [
    'base_url'      => env('SSO_BASE_URL', 'https://apply.epauzb.uz'),
    'client_id'     => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'redirect_uri'  => env('SSO_REDIRECT_URI'),
    'scope'         => env('SSO_SCOPE', ''),
],
```

Key environment variables (full list documented in `config/sso.php`):

| Env var | Default | Description |
| --- | --- | --- |
| `SSO_USER_MODEL` | `App\Models\User` | Model to upsert; must use `HasApiTokens` + spatie `HasRoles` |
| `SSO_TOKEN_EXPIRY_MINUTES` | `60` | Session token (and cookie) lifetime |
| `SSO_UNLOCK_TOKEN_TTL` | `720` | Unlock token absolute cap, minutes (12h) |
| `SSO_SESSION_COOKIE` / `SSO_UNLOCK_COOKIE` | `session_token` / `unlock_token` | Cookie names |
| `SSO_COOKIE_DOMAIN` | _(host)_ | Cookie domain (e.g. `.td.uz` to share across subdomains) |
| `SSO_COOKIE_SECURE` | `true` | `Secure` flag (HTTPS only) |
| `SSO_COOKIE_SAMESITE` | `strict` | `SameSite` (`strict`/`lax` same-site; `none` for cross-site) |
| `SSO_PIN_MIN_LENGTH` / `SSO_PIN_MAX_LENGTH` | `4` / `4` | PIN length bounds (4-digit numeric by default) |
| `SSO_PIN_MAX_ATTEMPTS` / `SSO_PIN_LOCKOUT_MINUTES` | `5` / `15` | Lockout policy |
| `SSO_IDLE_ENABLED` / `SSO_IDLE_TIMEOUT` | `true` / `15` | Server-side idle backstop |
| `SSO_AUTO_CREATE_USER` | `false` | Auto-provision unknown users |
| `SSO_SYNC_ROLES` | `false` | Sync roles from the SSO payload |
| `SSO_ACTIVE_COLUMN` | _(null)_ | Boolean column checked by the login gate (null = off) |
| `SSO_LOGS_MINE_ENABLED` / `SSO_LOGS_ADMIN_ENABLED` | `false` / `false` | Auth-log read endpoints |
| `SSO_AUTH_LOG_PERMISSION` | `sso_logs.list` | Permission for `GET logs` |
| `SSO_AUTH_LOG_RETENTION_DAYS` | `180` | Prune window for `sso_auth_logs` |

### Same-site vs cross-site (CSRF)

When the SPA and API share a site (e.g. `admin.td.uz` / `api.td.uz`), keep
`SameSite=strict` — it blocks cross-site CSRF while same-site requests still
carry the cookie. Because the origins differ, you still need CORS with
credentials: `Access-Control-Allow-Credentials: true`, an explicit
`Access-Control-Allow-Origin` (not `*`), and `withCredentials` on the frontend.
Use `SameSite=none` **only** for genuinely cross-site deployments.

## User model

```php
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable implements OAuthenticatable
{
    use HasApiTokens, HasRoles;
    // columns written by the upsert (each only if present): pin (key),
    // first_name, last_name, father_name, full_name, tin
}
```

## Testing

```bash
composer test      # Pest
composer analyse   # PHPStan (larastan)
composer format    # Pint
```

## License

The MIT License (MIT). See [LICENSE](LICENSE).
