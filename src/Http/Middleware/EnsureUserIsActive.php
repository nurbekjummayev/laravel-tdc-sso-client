<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Middleware;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\LoginDeniedException;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoService;
use Nurbekjummayev\LaravelTdcSsoClient\Support\SsoCookieFactory;
use Symfony\Component\HttpFoundation\Response;

/**
 * Per-request login gate, aliased as `sso.active`. Runs AFTER the auth
 * middleware: a user the gate now rejects (deactivated mid-session) loses every
 * token and both cookies, and gets a 403 with `code: account_inactive`.
 *
 * Applied to the package's own authenticated routes; hosts add it to theirs.
 */
class EnsureUserIsActive
{
    public function __construct(
        private readonly SsoService $ssoService,
        private readonly SsoCookieFactory $cookies,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof Model) {
            return $next($request);
        }

        try {
            $this->ssoService->ensureCanLogin($user, $request);
        } catch (LoginDeniedException $e) {
            return $e->render()
                ->withCookie($this->cookies->forgetSession())
                ->withCookie($this->cookies->forgetUnlock());
        }

        return $next($request);
    }
}
