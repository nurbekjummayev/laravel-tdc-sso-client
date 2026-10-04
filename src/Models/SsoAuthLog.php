<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Date;
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
 * @property array<string, mixed>|null $meta
 * @property Carbon|null $created_at
 * @property-read Token|null $accessToken
 * @property-read Model|null $user
 */
class SsoAuthLog extends Model
{
    use Prunable;

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
        'meta',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'meta' => 'array',
        ];
    }

    /**
     * Rows older than `sso.auth_log.retention_days` are pruned by
     * `model:prune`; a null retention keeps every row.
     *
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $days = config('sso.auth_log.retention_days');

        if (! is_numeric($days)) {
            return static::query()->whereRaw('1 = 0');
        }

        return static::query()->where('created_at', '<', Date::now()->subDays((int) $days));
    }

    /**
     * The local user the event belongs to (the configured `sso.user_model`).
     *
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        /** @var class-string<Model> $userModel */
        $userModel = (string) config('sso.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel, 'user_id');
    }

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
