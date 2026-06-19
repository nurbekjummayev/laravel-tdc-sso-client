<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Exceptions;

use RuntimeException;

/**
 * Thrown when a PIN is rejected: wrong PIN on unlock, wrong current PIN on
 * change, or a PIN that fails the configured format rules.
 */
class InvalidPinException extends RuntimeException {}
