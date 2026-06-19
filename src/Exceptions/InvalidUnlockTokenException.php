<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Exceptions;

use RuntimeException;

/**
 * Thrown when an unlock token is missing, expired, revoked, or replayed. The
 * caller must fall back to a full SSO re-login.
 */
class InvalidUnlockTokenException extends RuntimeException {}
