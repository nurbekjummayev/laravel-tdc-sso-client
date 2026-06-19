<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * Server-side idle-timeout backstop.
 *
 * The real-time screen lock lives on the frontend; this guarantees that even if
 * that lock is bypassed, a session token is revoked once no request has arrived
 * within the configured window. Runs AFTER the auth middleware (it needs the
 * authenticated token). Activity is tracked per token id in the cache.
 */
class EnforceIdleTimeout
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! (bool) config('sso.idle.enabled', true)) {
            return $next($request);
        }

        $user = $request->user();

        if ($user === null || ! method_exists($user, 'token')) {
            return $next($request);
        }

        $token = $user->token();

        if ($token === null || ! method_exists($token, 'getKey')) {
            return $next($request);
        }

        $timeout = (int) config('sso.idle.timeout', 15) * 60;
        $key = 'sso:activity:'.$token->getKey();
        $now = $request->server('REQUEST_TIME', null);
        $now = is_numeric($now) ? (int) $now : strtotime('now');

        $last = Cache::get($key);

        if (is_numeric($last) && ($now - (int) $last) > $timeout) {
            if (method_exists($token, 'revoke')) {
                $token->revoke();
            }

            Cache::forget($key);

            return $this->expired();
        }

        Cache::put($key, $now, $timeout * 2);

        return $next($request);
    }

    private function expired(): Response
    {
        if (function_exists('unauthorizedRequestResponse')) {
            return unauthorizedRequestResponse('Session expired due to inactivity');
        }

        return response()->json(['message' => 'Session expired due to inactivity'], 401);
    }
}
