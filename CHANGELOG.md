# Changelog

All notable changes to `laravel-tdc-sso-client` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Login gate** for inactive / deleted users: `sso.login_gate` (class-string,
  `LoginGate` contract) with the default `ActiveColumnGate` driven by
  `sso.active_column` (null = off). Checked on callback (before minting), on
  unlock (before the PIN) and per request via the new `sso.active` middleware.
  Rejections revoke all tokens, clear both cookies, log `login_denied`, and
  return 403 with `code: account_inactive | account_not_registered`.
- `SsoService::revokeAll($user, $onlySso = false)` — revoke every Passport and
  unlock token for a user (call on deactivation / deletion).
- `sso.me_resource` — override the `user` payload of callback / unlock / me by
  extending `SsoUserResource`.
- Auth-log read endpoints `GET logs/mine` and `GET logs` (permission
  `sso_logs.list`), with event / date / user filters and pagination; both off
  by default.
- `meta` json column on `sso_auth_logs` (new migration) filled by
  `sso.auth_log.meta_resolver`; `SsoAuthLog` is `Prunable`
  (`sso.auth_log.retention_days`, default 180) and has a `user` relation.

### Fixed
- The idle-timeout backstop never ran on Passport 13: `$user->token()` is an
  `AccessToken` wrapper without `getKey()`, so activity was never tracked. The
  token id is now read from `oauth_access_token_id` (new `CurrentToken`
  helper), also used by lock/logout.
- Soft-deleted users are found on callback and rejected, instead of being
  re-created (or hitting the unique pin index) when `auto_create_user=true`.
- Unlock for a user that no longer exists returns 403 instead of a generic 401.
- Freshly auto-provisioned users are refreshed so DB defaults are visible.

### Changed
- An unknown user on callback now throws `LoginDeniedException` (a subclass of
  `ForbiddenException`, so existing catches still work) and the 403 carries
  `code: account_not_registered` and clears the cookies.

### Added
- **Cookie-based session + screen-lock + PIN unlock flow:**
  - Two httpOnly cookies: short-lived `session_token` and 12h `unlock_token`.
  - Endpoints: `POST unlock`, `POST lock`, `POST set-pin`, `GET me` (now
    includes `has_pin`), `POST logout`.
  - `sso_lock_pins` table (bcrypt PIN, set/change timestamps, last IP / user
    agent, failed-attempt lockout) and `sso_unlock_tokens` table (rotating,
    reuse-detected, 12h absolute cap).
  - `AuthenticateSessionCookie` middleware (cookie → Bearer) and
    `EnforceIdleTimeout` server-side backstop.
  - `AuthEvent` events: `Lock`, `Unlock`, `PinSet`, `PinChanged`.
- `php artisan sso:install` command — one-shot setup: publishes Passport's
  migrations, runs migrate, generates Passport keys, and creates the personal
  access client (idempotent; `--force` for non-interactive/prod).
- Configurable outbound HTTP timeouts, authorize `scope`, cookie attributes,
  PIN policy, and idle timeout.
- Test suite (Pest + Orchestra Testbench), PHPStan/Larastan, Pint, and CI.

### Changed
- The login `callback` now sets httpOnly cookies and returns only the user
  payload — the token is no longer exposed in the JSON body.
- The bundled spatie/permission migration skips creation when its tables
  already exist.

### Removed
- The bundled Passport `oauth_*` migrations (auth codes, access tokens, refresh
  tokens, clients, device codes). They are Passport's own schema — install via
  `php artisan passport:install`.
- The Bearer-token-in-body `refresh` endpoint (replaced by the cookie-based
  lock/unlock model).

### Fixed
- Removed the hardcoded `version` from `composer.json`.

## [1.0.0]

- Initial release: TDC-SSO (OAuth2 Authorization Code + PKCE) BFF login flow
  (`redirect` + `callback`) issuing a backend Passport bearer token.
