<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog;

/**
 * @mixin SsoAuthLog
 */
class SsoAuthLogResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->user_id,
            'user' => $this->whenLoaded('user', fn (): ?array => $this->user === null ? null : [
                'id' => $this->user->getKey(),
                'full_name' => $this->user->getAttribute('full_name') ?? $this->user->getAttribute('name'),
            ]),
            'event' => $this->event,
            'ip_address' => $this->ip_address,
            'user_agent' => $this->user_agent,
            'meta' => $this->meta,
            'created_at' => $this->created_at,
        ];
    }
}
