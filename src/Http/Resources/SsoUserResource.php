<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Resources;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nurbekjummayev\LaravelTdcSsoClient\Services\PinManager;

/**
 * The `user` payload returned by callback, unlock and me.
 *
 * Override via `sso.me_resource` with a subclass that adds host fields:
 *
 *     public function toArray(Request $request): array
 *     {
 *         return [...parent::toArray($request), 'email' => $this->email];
 *     }
 *
 * @mixin Model
 */
class SsoUserResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $user = $this->resource;

        $permissions = method_exists($user, 'getAllPermissions')
            ? $user->getAllPermissions()->pluck('name')->all()
            : [];

        $role = method_exists($user, 'getRoleNames')
            ? $user->getRoleNames()->first()
            : null;

        return [
            'id' => $user->id,
            'first_name' => $user->first_name,
            'last_name' => $user->last_name,
            'father_name' => $user->father_name ?? null,
            'full_name' => $user->full_name,
            'pin' => $user->pin,
            'tin' => $user->tin ?? null,
            'created_at' => $user->created_at,
            'updated_at' => $user->updated_at,
            'role' => $role,
            'permissions' => $permissions,
            'has_pin' => app(PinManager::class)->has((int) $user->getKey()),
        ];
    }
}
