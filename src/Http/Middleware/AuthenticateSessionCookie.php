<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Copies the session token from the httpOnly cookie into the Authorization
 * header so Passport's `auth:api` guard can authenticate the request.
 *
 * Runs before the auth middleware. An explicit Bearer header (e.g. from a
 * mobile client) always takes precedence and is left untouched.
 */
class AuthenticateSessionCookie
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->bearerToken() === null) {
            $cookieName = (string) config('sso.cookies.session_name', 'session_token');
            $token = $request->cookie($cookieName);

            if (is_string($token) && $token !== '') {
                $request->headers->set('Authorization', 'Bearer '.$token);
            }
        }

        return $next($request);
    }
}
