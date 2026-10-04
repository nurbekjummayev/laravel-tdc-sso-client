<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Auth;

use Illuminate\Database\Eloquent\Model;
use Nurbekjummayev\LaravelTdcSsoClient\Contracts\LoginGate;

/**
 * Default gate: allows the user when the `sso.active_column` attribute is
 * truthy. A null column disables the check entirely.
 */
class ActiveColumnGate implements LoginGate
{
    public function allows(Model $user): bool
    {
        $column = config('sso.active_column');

        if (! is_string($column) || $column === '') {
            return true;
        }

        return (bool) $user->getAttribute($column);
    }
}
