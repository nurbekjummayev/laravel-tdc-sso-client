<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;

/**
 * The screen-lock PIN for a single user.
 *
 * @property int $id
 * @property int $user_id
 * @property string $pin_hash
 * @property int $failed_attempts
 * @property Carbon|null $locked_until
 * @property string|null $last_ip
 * @property string|null $last_user_agent
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class SsoLockPin extends Model
{
    protected $table = 'sso_lock_pins';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'pin_hash',
        'failed_attempts',
        'locked_until',
        'last_ip',
        'last_user_agent',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'failed_attempts' => 'integer',
            'locked_until' => 'datetime',
        ];
    }

    /**
     * Whether the PIN is currently locked out due to too many failed attempts.
     */
    public function isLockedOut(): bool
    {
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }

    public function markUnlockSucceeded(): void
    {
        $this->forceFill([
            'failed_attempts' => 0,
            'locked_until' => null,
        ])->save();
    }

    public function markUnlockFailed(int $maxAttempts, int $lockoutMinutes): void
    {
        $attempts = $this->failed_attempts + 1;

        $this->forceFill([
            'failed_attempts' => $attempts,
            'locked_until' => $attempts >= $maxAttempts
                ? Date::now()->addMinutes($lockoutMinutes)
                : null,
        ])->save();
    }
}
