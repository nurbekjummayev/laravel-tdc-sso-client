<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Enums;

/**
 * The authentication events recorded in the sso_auth_logs table.
 */
enum AuthEvent: string
{
    case Login = 'login';
    case Logout = 'logout';
    case Lock = 'lock';
    case Unlock = 'unlock';
    case PinSet = 'pin_set';
    case PinChanged = 'pin_changed';
}
