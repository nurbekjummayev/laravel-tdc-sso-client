<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures;

use Illuminate\Http\Request;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoUserResource;

class ExtendedUserResource extends SsoUserResource
{
    public function toArray(Request $request): array
    {
        return [...parent::toArray($request), 'email' => $this->resource->email];
    }
}
