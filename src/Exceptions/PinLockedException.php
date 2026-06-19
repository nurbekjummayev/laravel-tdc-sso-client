<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Exceptions;

use RuntimeException;

/**
 * Thrown when the PIN is temporarily locked after too many failed unlock
 * attempts.
 */
class PinLockedException extends RuntimeException {}
