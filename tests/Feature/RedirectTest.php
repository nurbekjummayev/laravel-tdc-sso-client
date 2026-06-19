<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;

it('redirects to the SSO authorize endpoint and caches the PKCE verifier', function (): void {
    $response = $this->get('/api/auth/sso/redirect');

    $response->assertRedirect();

    $location = $response->headers->get('Location');

    expect($location)->toStartWith('https://sso.example.test/oauth/authorize?');

    parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

    expect($query)
        ->toHaveKey('client_id', 'client-123')
        ->toHaveKey('redirect_uri', 'https://app.example.test/sso/callback')
        ->toHaveKey('response_type', 'code')
        ->toHaveKey('code_challenge_method', 'S256');

    expect($query['state'] ?? '')->not->toBe('');
    expect($query['code_challenge'] ?? '')->not->toBe('');

    // The PKCE verifier must be cached against the state for the callback step.
    expect(Cache::has('sso:state:'.$query['state']))->toBeTrue();
});
