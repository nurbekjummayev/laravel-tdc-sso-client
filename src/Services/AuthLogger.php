<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Http\Request;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog;

/**
 * Persists authentication events (login / logout) to the sso_auth_logs table.
 *
 * The request is used to capture the client IP address and user agent at the
 * moment the event occurs.
 */
class AuthLogger
{
    /**
     * Record an authentication event for the given user.
     *
     * @param  string|null  $tokenId  The Passport access token id involved in
     *                                the event (minted on login / revoked on
     *                                logout); null when no token applies.
     */
    public function record(AuthEvent $event, ?int $userId, ?Request $request = null, ?string $tokenId = null): void
    {
        if (! (bool) config('sso.auth_log.enabled', true)) {
            return;
        }

        $request ??= request();

        SsoAuthLog::query()->create([
            'user_id' => $userId,
            'token_id' => $tokenId,
            'event' => $event->value,
            'ip_address' => $request->ip(),
            'user_agent' => substr((string) $request->userAgent(), 0, 1000),
        ]);
    }
}
