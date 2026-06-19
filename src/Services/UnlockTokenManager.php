<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidUnlockTokenException;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoUnlockToken;

/**
 * Issues, verifies and rotates the long-lived unlock tokens.
 *
 * Tokens are high-entropy random strings stored as a SHA-256 lookup hash. Each
 * token carries an absolute expiry (the 12h cap from login); rotations preserve
 * that deadline so the session can never be slid past the cap. A replayed
 * (already-revoked) token triggers a full revocation of the user's chain as a
 * theft response.
 */
class UnlockTokenManager
{
    /**
     * Issue a brand-new unlock token (at login). Returns the plaintext token to
     * hand to the SPA as an httpOnly cookie.
     */
    public function issue(int $userId): string
    {
        return $this->create(
            $userId,
            Date::now()->addMinutes((int) config('sso.unlock_token_ttl_minutes', 720)),
        );
    }

    /**
     * Validate a presented token WITHOUT rotating it.
     *
     * Rotation is deferred until the PIN has also been verified, so a wrong PIN
     * does not burn the caller's unlock token (which would lock them out after a
     * single mistake).
     *
     * @throws InvalidUnlockTokenException when the token is unknown, expired, revoked or replayed
     */
    public function verify(string $plaintext): SsoUnlockToken
    {
        return $this->findValid($plaintext);
    }

    /**
     * Revoke the given token and mint a replacement that keeps the same absolute
     * deadline (the 12h cap never slides). Returns the new plaintext.
     */
    public function rotate(SsoUnlockToken $current): string
    {
        $current->forceFill(['revoked_at' => Date::now()])->save();

        return $this->create((int) $current->user_id, $current->expires_at);
    }

    /**
     * Revoke every active unlock token for a user (logout / theft response).
     */
    public function revokeAllForUser(int $userId): void
    {
        SsoUnlockToken::query()
            ->where('user_id', $userId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => Date::now()]);
    }

    /**
     * @throws InvalidUnlockTokenException
     */
    private function findValid(string $plaintext): SsoUnlockToken
    {
        $record = SsoUnlockToken::query()
            ->where('token_hash', $this->hash($plaintext))
            ->first();

        if ($record === null) {
            throw new InvalidUnlockTokenException('Unlock token topilmadi yoki yaroqsiz.');
        }

        if ($record->isRevoked()) {
            // A revoked token being presented again means it was captured and
            // replayed — revoke the whole chain and force a re-login.
            $this->revokeAllForUser((int) $record->user_id);

            throw new InvalidUnlockTokenException('Unlock token qayta ishlatilgan — sessiya bekor qilindi.');
        }

        if ($record->isExpired()) {
            throw new InvalidUnlockTokenException('Unlock token muddati tugagan.');
        }

        return $record;
    }

    private function create(int $userId, Carbon $expiresAt): string
    {
        $plaintext = Str::random(64);

        SsoUnlockToken::query()->create([
            'user_id' => $userId,
            'token_hash' => $this->hash($plaintext),
            'expires_at' => $expiresAt,
        ]);

        return $plaintext;
    }

    private function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }
}
