<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Contracts;

use Illuminate\Database\Eloquent\Model;

/**
 * Decides whether a local user may hold an SSO session.
 *
 * Consulted on callback (before a token is minted), on unlock (before the PIN
 * is checked) and on every authenticated request via the `sso.active`
 * middleware. Bound from the `sso.login_gate` config as a class-string so the
 * config stays cacheable.
 */
interface LoginGate
{
    public function allows(Model $user): bool;
}
