<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidPinException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidUnlockTokenException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\LoginDeniedException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\PinLockedException;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoUserResource;
use Nurbekjummayev\LaravelTdcSsoClient\Services\PinManager;
use Nurbekjummayev\LaravelTdcSsoClient\Services\SsoService;
use Nurbekjummayev\LaravelTdcSsoClient\Support\SsoCookieFactory;
use Throwable;

/**
 * TDC-SSO (OAuth2 Authorization Code + PKCE) cookie-based BFF endpoints.
 *
 * Login mints two httpOnly cookies: a short-lived `session_token` (the working
 * access token, killed on lock) and a long-lived `unlock_token` (used with the
 * PIN to re-mint a session). The SSO provider token is never exposed to the
 * browser, and neither session nor unlock token is ever readable by JavaScript.
 */
readonly class SsoController
{
    public function __construct(
        private SsoService $ssoService,
        private PinManager $pinManager,
        private SsoCookieFactory $cookies,
    ) {}

    /**
     * GET redirect — start the flow, send the browser to the SSO authorize URL.
     */
    public function redirect(): RedirectResponse
    {
        return redirect()->away($this->ssoService->buildRedirect());
    }

    /**
     * POST callback — exchange code+state, upsert the user, and set the session
     * and unlock cookies. The tokens are never returned in the body.
     */
    public function callback(Request $request): JsonResponse
    {
        $code = (string) $request->input('code', '');
        $state = (string) $request->input('state', '');

        if ($code === '' || $state === '') {
            return unauthorizedRequestResponse('Invalid SSO request');
        }

        try {
            $result = $this->ssoService->handleCallback($code, $state, $request);
        } catch (LoginDeniedException $e) {
            return $this->denied($e);
        } catch (Throwable $e) {
            report($e);

            return unauthorizedRequestResponse('SSO authentication failed');
        }

        return okResponse([
            'user' => $this->transformUser($result['user'], $request),
        ], 'OK')
            ->withCookie($this->cookies->sessionCookie($result['session_token']))
            ->withCookie($this->cookies->unlockCookie($result['unlock_token']));
    }

    /**
     * GET me — the authenticated user (resolved via the session cookie),
     * including whether a PIN has been configured.
     */
    public function me(Request $request): JsonResponse
    {
        return okResponse([
            'user' => $this->transformUser($request->user(), $request),
        ], 'OK');
    }

    /**
     * POST lock — revoke the session token and clear its cookie. The unlock
     * cookie is left intact so the PIN can re-mint a session.
     */
    public function lock(Request $request): JsonResponse
    {
        $this->ssoService->lock($request->user(), $request);

        return okResponse([], 'OK')
            ->withCookie($this->cookies->forgetSession());
    }

    /**
     * POST unlock — exchange the unlock cookie + PIN for a fresh session token.
     * Not behind auth:api: the session token is dead during a lock, so the
     * request is authenticated by the unlock token and the PIN.
     */
    public function unlock(Request $request): JsonResponse
    {
        $unlockToken = (string) $request->cookie($this->cookies->unlockName(), '');
        $pin = (string) $request->input('pin', '');

        if ($unlockToken === '') {
            return unauthorizedRequestResponse('Sessiya topilmadi. Qaytadan kiring.');
        }

        try {
            $result = $this->ssoService->unlock($unlockToken, $pin, $request);
        } catch (InvalidUnlockTokenException $e) {
            // Token gone/expired/replayed — force a full SSO re-login.
            return unauthorizedRequestResponse($e->getMessage())
                ->withCookie($this->cookies->forgetSession())
                ->withCookie($this->cookies->forgetUnlock());
        } catch (LoginDeniedException $e) {
            return $this->denied($e);
        } catch (PinLockedException $e) {
            return forbiddenRequestResponse($e->getMessage());
        } catch (InvalidPinException $e) {
            return unauthorizedRequestResponse($e->getMessage());
        } catch (Throwable $e) {
            report($e);

            return unauthorizedRequestResponse('Unlock failed');
        }

        return okResponse([
            'user' => $this->transformUser($result['user'], $request),
        ], 'OK')
            ->withCookie($this->cookies->sessionCookie($result['session_token']))
            ->withCookie($this->cookies->unlockCookie($result['unlock_token']));
    }

    /**
     * POST set-pin — set or change the screen-lock PIN.
     *
     * Body: `pin`, `pin_confirmation`, and (when changing an existing PIN)
     * `current_pin`.
     */
    public function setPin(Request $request): JsonResponse
    {
        $pin = (string) $request->input('pin', '');
        $pinConfirmation = (string) $request->input('pin_confirmation', '');

        $currentPin = $request->input('current_pin');
        $currentPin = is_string($currentPin) ? $currentPin : null;

        try {
            $this->pinManager->set($request->user(), $pin, $pinConfirmation, $currentPin, $request);
        } catch (InvalidPinException $e) {
            return forbiddenRequestResponse($e->getMessage());
        }

        return okResponse([], 'OK');
    }

    /**
     * POST logout — revoke the session and all unlock tokens, clear both cookies.
     */
    public function logout(Request $request): JsonResponse
    {
        $this->ssoService->logout($request->user(), $request);

        return okResponse([], 'OK')
            ->withCookie($this->cookies->forgetSession())
            ->withCookie($this->cookies->forgetUnlock());
    }

    /**
     * 403 with the denial `code`, clearing both cookies so the SPA cannot loop
     * between lock and unlock with a dead session.
     */
    private function denied(LoginDeniedException $e): JsonResponse
    {
        return $e->render()
            ->withCookie($this->cookies->forgetSession())
            ->withCookie($this->cookies->forgetUnlock());
    }

    /**
     * Build the public user payload through the configured `sso.me_resource`
     * (default {@see SsoUserResource}).
     *
     * @return array<string, mixed>
     */
    private function transformUser(mixed $user, Request $request): array
    {
        $resourceClass = (string) config('sso.me_resource', SsoUserResource::class);

        /** @var JsonResource $resource */
        $resource = new $resourceClass($user);

        return $resource->resolve($request);
    }
}
