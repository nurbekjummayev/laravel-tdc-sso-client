---
name: tdc-sso-client
description: >
  Integrate and use the private Laravel package nurbekjummayev/laravel-tdc-sso-client
  (TDC-SSO cookie-based BFF: OAuth2 Authorization Code + PKCE login, an httpOnly
  session_token + a 12h unlock_token, and a PIN-protected screen lock) inside a host
  Laravel backend app. Use this skill WHENEVER the user is wiring up TDC-SSO / epauzb
  login, the session/unlock cookies, the screen-lock + PIN flow, the unlock/lock/set-pin
  endpoints, installs this package from a private GitHub VCS repo, configures the Passport
  personal access client for it, or debugs cookie/CSRF/CORS issues for the admin↔api
  subdomain setup — even if they don't name the package explicitly.
---

# TDC-SSO Client integration

This skill helps wire `nurbekjummayev/laravel-tdc-sso-client` into a **host Laravel
backend** and connect a SPA frontend to it. The package is a Backend-for-Frontend (BFF):
it does the OAuth2 (Authorization Code + PKCE) exchange with the TDC-SSO provider
server-to-server, then issues the SPA **its own** session as two httpOnly cookies. The
SSO provider token is never exposed to the browser.

Read this whole file first, then jump to the section the user needs. The package's own
README (in the package repo) is the source of truth if anything here drifts.

## Mental model — the two tokens

The package never returns a token in a JSON body. It sets two httpOnly cookies:

- **`session_token`** — the working access token (a Passport personal access token).
  Short-lived. Sent automatically on every API request; a package middleware copies it
  into the `Authorization` header so `auth:api` (Passport) authenticates. **Killed on
  screen lock.**
- **`unlock_token`** — long-lived (12h hard cap from login). Scoped to the unlock route
  only. Used together with the user's **PIN** to re-mint a `session_token` after a lock,
  without a full SSO re-login. Rotated on every successful unlock; a replayed token
  revokes the whole chain (theft detection).

The lock **trigger** is the frontend's job (real-time inactivity detection). The backend
enforces a server-side **idle backstop** (revokes the session token after
`sso.idle.timeout` minutes of no requests).

## Endpoints

Prefix defaults to `api/auth/sso` (`sso.routes.prefix`).

| Method | URI | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `redirect` | public | Redirect the browser to the SSO authorize URL |
| POST | `callback` | public | Exchange `code`+`state`; set `session_token` + `unlock_token` cookies; returns `{ user }` |
| POST | `unlock` | unlock cookie + PIN | Re-mint a session after a lock. Body: `pin` |
| GET | `me` | session cookie | Current user, includes `has_pin` |
| POST | `set-pin` | session cookie | Set/change PIN. Body: `pin`, `pin_confirmation` (+ `current_pin` to change) |
| POST | `lock` | session cookie | Revoke the session token, clear its cookie (unlock cookie kept) |
| POST | `logout` | session cookie | Revoke session + all unlock tokens, clear both cookies |

`unlock` is intentionally public — during a lock the session token is dead, so the
request is authenticated by the unlock cookie + PIN, not `auth:api`. `me` carries
`has_pin` so the SPA chooses the **set-PIN** vs **unlock** screen with no extra request
(there is deliberately no `check-pin` endpoint).

## Installation (private GitHub VCS repo)

The package is **not on Packagist** (private). The host app pulls it via a VCS
repository. Add to the host `composer.json`:

```jsonc
{
    "repositories": [
        { "type": "vcs", "url": "git@github.com:nurbekjummayev/laravel-tdc-sso-client.git" }
    ],
    "require": {
        "nurbekjummayev/laravel-tdc-sso-client": "^1.0"
    }
}
```

Then:

```bash
composer update nurbekjummayev/laravel-tdc-sso-client
```

**Versioning.** The package has no hardcoded `version` — Composer reads versions from
**git tags**. So `"^1.0"` requires a tag like `v1.0.0` to exist on the package repo. If
there is no tag yet, either tag a release or, temporarily, require `"dev-main"` (and add
`"minimum-stability": "dev"` + `"prefer-stable": true` to the host). Prefer tagging.

**Private auth.** `git@github.com:...` needs SSH access where Composer runs:
- Local/server: an SSH key added to the GitHub account / a deploy key on the repo.
- CI/deploy: a deploy key, or switch to HTTPS + a token:
  `composer config --global github-oauth.github.com <TOKEN>`, or set `COMPOSER_AUTH`.

## One-time setup in the host app

The package ships only its OWN tables (`sso_auth_logs`, `sso_user_pins`,
`sso_unlock_tokens`). It does **not** bundle Passport's `oauth_*` tables — those are
Passport's. So:

```bash
# Passport's schema (publish then migrate):
php artisan vendor:publish --tag=passport-migrations

php artisan vendor:publish --tag=tdc-sso-client-config   # publishes config/sso.php
php artisan migrate

# Generate Passport keys + the personal access client (idempotent):
php artisan sso:install
```

`sso:install` is the package's own command. It runs `passport:keys` and creates the
`personal_access` client in `oauth_clients` (skips if one already exists). Pass `--force`
to regenerate keys. It fails clearly if `oauth_clients` is missing → run `migrate` first.

## Host User model (required contract)

The configured model (`sso.user_model`, default `App\Models\User`) MUST implement
Passport's `OAuthenticatable` (i.e. use `HasApiTokens`) and spatie's `HasRoles`, and have
the columns the upsert writes:

```php
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable implements OAuthenticatable
{
    use HasApiTokens, HasRoles;
    // columns the SSO upsert writes (each only if the column exists):
    // pin (unique key), first_name, last_name, father_name, full_name, tin
}
```

If the model is missing `OAuthenticatable`, token minting throws a clear RuntimeException
— that's the first thing to check when `callback`/`unlock` 500s.

## Configuration

Provider credentials live in the host `config/services.php` under `sso`:

```php
'sso' => [
    'base_url'      => env('SSO_BASE_URL', 'https://apply.epauzb.uz'),
    'client_id'     => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'redirect_uri'  => env('SSO_REDIRECT_URI'),   // points at the SPA's /sso/callback
    'scope'         => env('SSO_SCOPE', ''),
],
```

Package behaviour is `config/sso.php`. Most-used env vars:

| Env | Default | Meaning |
| --- | --- | --- |
| `SSO_TOKEN_EXPIRY_MINUTES` | 60 | session token + cookie lifetime |
| `SSO_UNLOCK_TOKEN_TTL` | 720 | unlock token absolute cap (minutes, 12h) |
| `SSO_COOKIE_DOMAIN` | host | e.g. `.td.uz` to share cookies across subdomains |
| `SSO_COOKIE_SECURE` | true | HTTPS-only cookies |
| `SSO_COOKIE_SAMESITE` | strict | `strict`/`lax` for same-site; `none` only for cross-site |
| `SSO_PIN_MIN_LENGTH`/`SSO_PIN_MAX_LENGTH` | 4/4 | PIN is a 4-digit numeric code by default |
| `SSO_PIN_MAX_ATTEMPTS`/`SSO_PIN_LOCKOUT_MINUTES` | 5/15 | unlock lockout policy |
| `SSO_IDLE_ENABLED`/`SSO_IDLE_TIMEOUT` | true/15 | server-side idle backstop |
| `SSO_AUTO_CREATE_USER` | false | auto-provision unknown users (else 403) |

## Frontend wiring (the part that trips people up)

The SPA never sees the tokens — the browser carries the cookies automatically. So:

1. **Always send credentials.** `fetch(url, { credentials: 'include' })` or axios
   `withCredentials: true`. Without this the cookies are NOT sent and every call 401s.
2. **CORS for credentials** (when SPA and API are different origins, e.g.
   `admin.td.uz` ↔ `api.td.uz`): the API must return
   `Access-Control-Allow-Credentials: true` and an explicit
   `Access-Control-Allow-Origin` (NOT `*`). Configure `config/cors.php`
   (`supports_credentials => true`, list the SPA origin).
3. **SameSite vs CSRF.** `admin.td.uz` and `api.td.uz` are the *same site* (shared
   `td.uz`), so `SameSite=strict` still lets the SPA's requests carry the cookie while
   blocking cross-site CSRF. Do **not** switch to `SameSite=none` for subdomains — that
   needlessly weakens CSRF. Use `none` only for genuinely different sites.
4. **Login flow:** send the user to `GET …/redirect` (full navigation, not XHR — it's a
   302 to the provider). The provider redirects back to the SPA's `redirect_uri` with
   `code`+`state`; the SPA POSTs those to `…/callback`. Cookies are set; the SPA then
   reads `GET …/me`.
5. **Screen lock UX:** a real-time inactivity timer in the SPA (reset on
   mousemove/keydown/scroll). On timeout: show the lock overlay, call `POST …/lock`
   (kills the session token server-side), and block API calls until unlocked. On PIN
   submit: `POST …/unlock` with `{ pin }` (the unlock cookie rides along automatically).
   On success the new session cookie is set; resume.
6. **PIN setup:** after login read `me`; if `has_pin === false` show a set-PIN screen →
   `POST …/set-pin` with `{ pin, pin_confirmation }`. To change later, include
   `current_pin`.
7. **Interpreting responses:** a 401 from a protected endpoint means the session token is
   gone (locked/expired/idle backstop) → show the lock/PIN screen. A 401 from `unlock`
   with an invalid-token message means the unlock token is gone/expired/replayed → force a
   full SSO re-login. A 403 from `unlock` means the PIN is locked out.

## Debugging checklist

- **Every request 401s:** frontend isn't sending cookies → missing
  `credentials: 'include'` / `withCredentials`, or CORS lacks
  `supports_credentials` + explicit origin.
- **`callback`/`unlock` 500:** user model doesn't implement `OAuthenticatable`, or
  `sso:install` wasn't run (no personal access client / no Passport keys).
- **`migrate` fails on Passport tables:** `vendor:publish --tag=passport-migrations`
  wasn't run.
- **One wrong PIN locks the user out completely:** that should NOT happen — the unlock
  token is only rotated AFTER the PIN verifies, so a wrong PIN leaves the cookie usable
  for retry. If it does, the frontend is calling `unlock` twice or rotating cookies on
  its own.
- **Composer can't find the package:** missing `repositories` VCS entry, missing git
  tag for the `^1.0` constraint, or no SSH/token auth to the private repo.
- **Session dies too fast / too slow:** tune `SSO_TOKEN_EXPIRY_MINUTES` and
  `SSO_IDLE_TIMEOUT`. The unlock window is `SSO_UNLOCK_TOKEN_TTL` (hard cap).

## What NOT to do

- Don't store the tokens in `localStorage`/JS — the whole design keeps them httpOnly so
  XSS can't read them. If you find code reading a token in JS, that's a regression.
- Don't add a `pin_hash` column to `users` — the PIN lives in `sso_user_pins`, and
  `has_pin` is derived from it (no duplicated flag to drift).
- Don't re-extend the 12h unlock cap on each unlock — it's an absolute ceiling from login
  by design; sliding it would make sessions immortal.
