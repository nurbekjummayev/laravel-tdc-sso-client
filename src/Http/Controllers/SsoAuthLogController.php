<?php

declare(strict_types=1);

namespace Nurbekjummayev\LaravelTdcSsoClient\Http\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Nurbekjummayev\LaravelTdcSsoClient\Enums\AuthEvent;
use Nurbekjummayev\LaravelTdcSsoClient\Http\Resources\SsoAuthLogResource;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoAuthLog;

/**
 * Read access to the sso_auth_logs table.
 *
 *   GET logs/mine — the caller's own history (no permission needed)
 *   GET logs      — every user's history, behind `sso.auth_log.permission`
 *
 * Query: event (string or array), from / to (dates, inclusive), per_page
 * (max 100), and user_id on the admin endpoint.
 */
readonly class SsoAuthLogController
{
    public function index(Request $request): JsonResponse
    {
        $filters = $this->validate($request, withUser: true);

        $query = $this->query($filters)->with('user');

        if (isset($filters['user_id'])) {
            $query->where('user_id', (int) $filters['user_id']);
        }

        return $this->paginate($query, $filters, $request);
    }

    public function mine(Request $request): JsonResponse
    {
        $filters = $this->validate($request, withUser: false);

        $query = $this->query($filters)->where('user_id', (int) $request->user()->getKey());

        return $this->paginate($query, $filters, $request);
    }

    /**
     * @return array<string, mixed>
     */
    private function validate(Request $request, bool $withUser): array
    {
        $events = array_map(static fn (AuthEvent $event): string => $event->value, AuthEvent::cases());

        $rules = [
            'event' => ['sometimes', 'array'],
            'event.*' => ['string', Rule::in($events)],
            'from' => ['sometimes', 'date'],
            'to' => ['sometimes', 'date', 'after_or_equal:from'],
            'per_page' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];

        if ($withUser) {
            $rules['user_id'] = ['sometimes', 'integer'];
        }

        // Accept ?event=login as well as ?event[]=login&event[]=logout.
        if (is_string($request->query('event'))) {
            $request->merge(['event' => [$request->query('event')]]);
        }

        return $request->validate($rules);
    }

    /**
     * @param  array<string, mixed>  $filters
     * @return Builder<SsoAuthLog>
     */
    private function query(array $filters): Builder
    {
        return SsoAuthLog::query()
            ->when(isset($filters['event']), fn (Builder $q) => $q->whereIn('event', $filters['event']))
            ->when(isset($filters['from']), fn (Builder $q) => $q->whereDate('created_at', '>=', $filters['from']))
            ->when(isset($filters['to']), fn (Builder $q) => $q->whereDate('created_at', '<=', $filters['to']))
            ->latest('id');
    }

    /**
     * @param  Builder<SsoAuthLog>  $query
     * @param  array<string, mixed>  $filters
     */
    private function paginate(Builder $query, array $filters, Request $request): JsonResponse
    {
        $page = $query->paginate((int) ($filters['per_page'] ?? 20))
            ->through(fn (SsoAuthLog $log): array => (new SsoAuthLogResource($log))->resolve($request));

        return okWithPaginateResponse($page);
    }
}
