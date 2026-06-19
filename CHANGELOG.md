# Changelog

All notable changes to `laravel-tdc-sso-client` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
