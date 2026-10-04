<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Exceptions;

use NurbekJummayev\ApiResponseHelper\Exceptions\ForbiddenException;

/**
 * Thrown when a user may not hold an SSO session. Renders as a 403 carrying a
 * machine-readable `code` so the SPA can tell the cases apart.
 */
class LoginDeniedException extends ForbiddenException
{
    public const INACTIVE = 'account_inactive';

    public const NOT_REGISTERED = 'account_not_registered';

    public function __construct(public readonly string $reason, ?string $message = null)
    {
        parent::__construct(
            message: $message ?? self::defaultMessage($reason),
            extraData: ['code' => $reason],
        );
    }

    public static function inactive(): self
    {
        return new self(self::INACTIVE);
    }

    public static function notRegistered(): self
    {
        return new self(self::NOT_REGISTERED);
    }

    private static function defaultMessage(string $reason): string
    {
        return match ($reason) {
            self::NOT_REGISTERED => 'Foydalanuvchi tizimda ro\'yxatdan o\'tmagan.',
            default => 'Foydalanuvchi faol emas. Tizimga kirish taqiqlangan.',
        };
    }
}
