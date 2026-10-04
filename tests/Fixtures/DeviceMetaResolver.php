<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures;

use Illuminate\Http\Request;
use Nurbekjummayev\LaravelTdcSsoClient\Contracts\AuthLogMetaResolver;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;

class DeviceMetaResolver implements AuthLogMetaResolver
{
    public function resolve(AuthEvent $event, ?int $userId, Request $request): array
    {
        return ['device' => 'desktop'];
    }
}
