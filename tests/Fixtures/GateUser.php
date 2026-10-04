<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class GateUser extends Authenticatable implements OAuthenticatable
{
    use HasApiTokens, HasRoles, SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];

    protected string $guard_name = 'api';

    protected $casts = ['is_active' => 'boolean'];
}
