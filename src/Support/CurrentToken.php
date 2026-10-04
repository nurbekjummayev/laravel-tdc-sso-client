<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * Reads the access token the current request authenticated with, across
 * Passport versions.
 *
 * Passport 13 hands the user a `Laravel\Passport\AccessToken` wrapper (id in
 * `oauth_access_token_id`, Eloquent methods only via __call), older versions
 * the Eloquent `Token` itself. A `TransientToken` (cookie-less first-party
 * auth) has no id at all.
 */
final class CurrentToken
{
    public static function of(mixed $user): ?object
    {
        if (! is_object($user) || ! method_exists($user, 'token')) {
            return null;
        }

        $token = $user->token();

        return is_object($token) ? $token : null;
    }

    public static function id(?object $token): ?string
    {
        if ($token === null) {
            return null;
        }

        if ($token instanceof Model) {
            $key = $token->getKey();

            return $key === null ? null : (string) $key;
        }

        $id = $token->oauth_access_token_id ?? null;

        return is_scalar($id) && $id !== '' ? (string) $id : null;
    }

    public static function revoke(?object $token): void
    {
        if ($token !== null && method_exists($token, 'revoke')) {
            $token->revoke();
        }
    }
}
