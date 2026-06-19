<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Server-to-server client for the TDC-SSO OAuth2 provider.
 *
 * The backend acts as a confidential client (BFF): it performs the
 * Authorization Code + PKCE exchange and never exposes the SSO token to
 * the browser.
 */
class SsoClient
{
    /**
     * Build the SSO /oauth/authorize URL the browser is redirected to.
     */
    public function buildAuthorizeUrl(string $state, string $codeChallenge): string
    {
        $query = http_build_query([
            'client_id' => (string) config('services.sso.client_id'),
            'redirect_uri' => (string) config('services.sso.redirect_uri'),
            'response_type' => 'code',
            'scope' => (string) config('services.sso.scope', ''),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        return $this->baseUrl().'/oauth/authorize?'.$query;
    }

    /**
     * Exchange an authorization code for an SSO access token.
     *
     * @return array{token_type?: string, expires_in?: int, access_token: string, refresh_token?: string}
     *
     * @throws RuntimeException
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        try {
            $response = Http::asForm()->acceptJson()->timeout($this->timeout())->connectTimeout($this->connectTimeout())->post($this->baseUrl().'/oauth/token', [
                'grant_type' => 'authorization_code',
                'client_id' => (string) config('services.sso.client_id'),
                'client_secret' => (string) config('services.sso.client_secret'),
                'redirect_uri' => (string) config('services.sso.redirect_uri'),
                'code' => $code,
                'code_verifier' => $codeVerifier,
            ]);
        } catch (ConnectionException $e) {
            throw new RuntimeException('Unable to reach the SSO token endpoint.', previous: $e);
        }

        if ($response->failed()) {
            throw new RuntimeException('SSO token exchange failed.');
        }

        /** @var array{access_token?: string} $data */
        $data = $response->json();

        if (empty($data['access_token'])) {
            throw new RuntimeException('SSO token exchange returned no access token.');
        }

        /** @var array{token_type?: string, expires_in?: int, access_token: string, refresh_token?: string} $data */
        return $data;
    }

    /**
     * Refresh an SSO access token using a refresh token.
     *
     * @return array{token_type?: string, expires_in?: int, access_token: string, refresh_token?: string}
     *
     * @throws RuntimeException
     */
    public function refreshToken(string $refreshToken): array
    {
        try {
            $response = Http::asForm()->acceptJson()->timeout($this->timeout())->connectTimeout($this->connectTimeout())->post($this->baseUrl().'/oauth/token/refresh', [
                'grant_type' => 'refresh_token',
                'client_id' => (string) config('services.sso.client_id'),
                'client_secret' => (string) config('services.sso.client_secret'),
                'refresh_token' => $refreshToken,
            ]);
        } catch (ConnectionException $e) {
            throw new RuntimeException('Unable to reach the SSO refresh endpoint.', previous: $e);
        }

        if ($response->failed()) {
            throw new RuntimeException('SSO token refresh failed.');
        }

        /** @var array{token_type?: string, expires_in?: int, access_token: string, refresh_token?: string} $data */
        $data = $response->json();

        return $data;
    }

    /**
     * Fetch the user identity from the one-shot /oauth/userinfo endpoint.
     *
     * This endpoint returns the identity data exactly once per token, so it
     * must be called immediately after the token exchange and persisted.
     *
     * The provider returns: pin, tin, full_name, first_name, last_name,
     * father_name, raw.
     *
     * @return array{pin?: string, tin?: string, full_name?: string, first_name?: string, last_name?: string, father_name?: string, raw?: mixed}
     *
     * @throws RuntimeException
     */
    public function fetchUserInfo(string $ssoAccessToken): array
    {
        try {
            $response = Http::withToken($ssoAccessToken)
                ->acceptJson()
                ->timeout($this->timeout())
                ->connectTimeout($this->connectTimeout())
                ->get($this->baseUrl().'/oauth/userinfo');
        } catch (ConnectionException $e) {
            throw new RuntimeException('Unable to reach the SSO userinfo endpoint.', previous: $e);
        }

        if ($response->failed()) {
            throw new RuntimeException('SSO userinfo request failed.');
        }

        /** @var array<string, mixed> $json */
        $json = $response->json();

        // The SSO provider wraps the identity payload in the standard API
        // response envelope ({ msg, error, success, data }); unwrap the inner
        // `data` object, falling back to the whole body if it isn't enveloped.
        /** @var array{pin?: string, tin?: string, full_name?: string, first_name?: string, last_name?: string, father_name?: string, raw?: mixed} $data */
        $data = (isset($json['data']) && is_array($json['data'])) ? $json['data'] : $json;

        return $data;
    }

    /**
     * Generate a high-entropy PKCE code verifier.
     */
    public function generateCodeVerifier(): string
    {
        return Str::random(96);
    }

    /**
     * Derive the S256 PKCE code challenge from a verifier:
     * base64url(sha256(verifier)) without padding.
     */
    public function codeChallenge(string $codeVerifier): string
    {
        $hash = hash('sha256', $codeVerifier, true);

        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * The configured SSO base URL with any trailing slash removed.
     */
    private function baseUrl(): string
    {
        return rtrim((string) config('services.sso.base_url'), '/');
    }

    /**
     * Max seconds to wait for a full SSO HTTP response.
     */
    private function timeout(): int
    {
        return (int) config('sso.http.timeout', 10);
    }

    /**
     * Max seconds to wait while establishing the SSO connection.
     */
    private function connectTimeout(): int
    {
        return (int) config('sso.http.connect_timeout', 5);
    }
}
