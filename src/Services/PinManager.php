<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidPinException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\PinLockedException;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoLockPin;

/**
 * Manages the screen-lock PIN stored in the sso_lock_pins table.
 *
 * The PIN is hashed with bcrypt (it is low entropy, so a slow hash is the right
 * choice). The table is the single source of truth for "does this user have a
 * PIN" — no flag is duplicated onto the users table.
 */
class PinManager
{
    public function __construct(
        private readonly AuthLogger $authLogger,
    ) {}

    /**
     * Whether the user has a PIN configured.
     */
    public function has(int $userId): bool
    {
        return SsoLockPin::query()->where('user_id', $userId)->exists();
    }

    /**
     * Create or change the user's PIN.
     *
     * The PIN must match its confirmation. Changing an existing PIN also
     * requires the current PIN, so a hijacked session cannot silently overwrite
     * it. The IP and user agent of this set/change are recorded.
     *
     * @throws InvalidPinException when the format is invalid, the confirmation
     *                             does not match, or the current PIN is wrong
     */
    public function set(Model $user, string $pin, string $pinConfirmation, ?string $currentPin, ?Request $request = null): void
    {
        $this->assertValidFormat($pin);

        if ($pin !== $pinConfirmation) {
            throw new InvalidPinException('PIN va tasdiqlash PIN mos kelmadi.');
        }

        $userId = (int) $user->getKey();
        $existing = SsoLockPin::query()->where('user_id', $userId)->first();

        if ($existing !== null) {
            if ($currentPin === null || ! Hash::check($currentPin, $existing->pin_hash)) {
                throw new InvalidPinException('Joriy PIN noto\'g\'ri.');
            }
        }

        $request ??= request();

        SsoLockPin::query()->updateOrCreate(
            ['user_id' => $userId],
            [
                'pin_hash' => Hash::make($pin),
                'failed_attempts' => 0,
                'locked_until' => null,
                'last_ip' => $request->ip(),
                'last_user_agent' => substr((string) $request->userAgent(), 0, 1000),
            ],
        );

        $this->authLogger->record(
            $existing === null ? AuthEvent::PinSet : AuthEvent::PinChanged,
            $userId,
            $request,
        );
    }

    /**
     * Verify a PIN for the unlock flow, enforcing the lockout policy.
     *
     * @throws PinLockedException when the PIN is locked after too many attempts
     * @throws InvalidPinException when the PIN is wrong (after recording the attempt)
     */
    public function verify(int $userId, string $pin): void
    {
        $record = SsoLockPin::query()->where('user_id', $userId)->first();

        if ($record === null) {
            throw new InvalidPinException('PIN o\'rnatilmagan.');
        }

        if ($record->isLockedOut()) {
            throw new PinLockedException('PIN vaqtincha bloklangan. Birozdan so\'ng urinib ko\'ring.');
        }

        if (! Hash::check($pin, $record->pin_hash)) {
            $record->markUnlockFailed(
                (int) config('sso.pin.max_attempts', 5),
                (int) config('sso.pin.lockout_minutes', 15),
            );

            throw new InvalidPinException('PIN noto\'g\'ri.');
        }

        $record->markUnlockSucceeded();
    }

    /**
     * @throws InvalidPinException
     */
    private function assertValidFormat(string $pin): void
    {
        $min = (int) config('sso.pin.min_length', 4);
        $max = (int) config('sso.pin.max_length', 8);

        if (! ctype_digit($pin)) {
            throw new InvalidPinException('PIN faqat raqamlardan iborat bo\'lishi kerak.');
        }

        $length = strlen($pin);

        if ($length < $min || $length > $max) {
            $expected = $min === $max ? "{$min}" : "{$min}–{$max}";

            throw new InvalidPinException("PIN uzunligi {$expected} ta raqam bo'lishi kerak.");
        }
    }
}
