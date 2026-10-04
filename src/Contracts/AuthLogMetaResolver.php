<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Contracts;

use Illuminate\Http\Request;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;

/**
 * Supplies extra data (geolocation, device, ...) stored in the `meta` column
 * of every sso_auth_logs row. Bound from `sso.auth_log.meta_resolver`.
 */
interface AuthLogMetaResolver
{
    /**
     * @return array<string, mixed>
     */
    public function resolve(AuthEvent $event, ?int $userId, Request $request): array;
}
