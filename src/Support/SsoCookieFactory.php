<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Support;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * Builds the httpOnly session / unlock cookies from package config.
 *
 * The session cookie is scoped to "/" (sent on every API request); the unlock
 * cookie is scoped tightly to the unlock route so the browser only sends it
 * there. Both are httpOnly + SameSite so JavaScript cannot read them and
 * cross-site requests cannot carry them.
 */
class SsoCookieFactory
{
    public function sessionCookie(string $token): Cookie
    {
        return $this->make(
            $this->sessionName(),
            $token,
            (int) config('sso.token_expiry_minutes', 60),
            '/',
        );
    }

    public function forgetSession(): Cookie
    {
        return $this->make($this->sessionName(), '', -1, '/');
    }

    public function unlockCookie(string $token): Cookie
    {
        return $this->make(
            $this->unlockName(),
            $token,
            (int) config('sso.unlock_token_ttl_minutes', 720),
            $this->unlockPath(),
        );
    }

    public function forgetUnlock(): Cookie
    {
        return $this->make($this->unlockName(), '', -1, $this->unlockPath());
    }

    public function sessionName(): string
    {
        return (string) config('sso.cookies.session_name', 'session_token');
    }

    public function unlockName(): string
    {
        return (string) config('sso.cookies.unlock_name', 'unlock_token');
    }

    /**
     * The unlock cookie is only ever sent to the unlock endpoint.
     */
    public function unlockPath(): string
    {
        $prefix = trim((string) config('sso.routes.prefix', 'api/auth/sso'), '/');

        return '/'.$prefix.'/unlock';
    }

    private function make(string $name, string $value, int $minutes, string $path): Cookie
    {
        return new Cookie(
            name: $name,
            value: $value,
            expire: $minutes === -1 ? 1 : time() + ($minutes * 60),
            path: $path,
            domain: config('sso.cookies.domain'),
            secure: (bool) config('sso.cookies.secure', true),
            httpOnly: true,
            raw: false,
            sameSite: (string) config('sso.cookies.same_site', 'strict'),
        );
    }
}
