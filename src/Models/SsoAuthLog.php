<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;

/**
 * Authentication event audit log for the TDC-SSO flow.
 *
 * @property int $id
 * @property int|null $user_id
 * @property string|null $token_id
 * @property string $event
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property Carbon|null $created_at
 * @property-read Token|null $accessToken
 */
class SsoAuthLog extends Model
{
    /**
     * The table only tracks creation time; there is no updated_at column.
     */
    public const UPDATED_AT = null;

    /**
     * The table associated with the model.
     */
    protected $table = 'sso_auth_logs';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'token_id',
        'event',
        'ip_address',
        'user_agent',
    ];

    /**
     * The Passport access token involved in this authentication event.
     *
     * Uses the configured Passport token model so a host app override is
     * honoured. No database foreign key backs this relation (see migration),
     * so the related token may be absent if it was pruned or revoked-and-purged.
     *
     * @return BelongsTo<Token, $this>
     */
    public function accessToken(): BelongsTo
    {
        /** @var class-string<Token> $tokenModel */
        $tokenModel = Passport::tokenModel();

        return $this->belongsTo($tokenModel, 'token_id', 'id');
    }
}
