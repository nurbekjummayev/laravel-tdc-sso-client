<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\InvalidPinException;
use Nurbekjummayev\LaravelTdcSsoClient\Exceptions\PinLockedException;
use Nurbekjummayev\LaravelTdcSsoClient\Models\SsoUserPin;
use Nurbekjummayev\LaravelTdcSsoClient\Services\PinManager;

/**
 * Minimal stand-in for the host user model — PinManager only needs getKey().
 */
class PinTestUser extends Model
{
    protected $table = 'users';

    protected $guarded = [];

    public $timestamps = false;
}

function pinUser(int $id = 7): PinTestUser
{
    $user = new PinTestUser(['id' => $id]);
    $user->exists = true;

    return $user;
}

beforeEach(function (): void {
    (require __DIR__.'/../../database/migrations/2026_06_19_000001_create_sso_user_pins_table.php')->up();
});

it('sets a PIN and reports has_pin', function (): void {
    $manager = app(PinManager::class);

    expect($manager->has(7))->toBeFalse();

    $manager->set(pinUser(), '1234', '1234', null);

    expect($manager->has(7))->toBeTrue();
});

it('verifies the correct PIN', function (): void {
    $manager = app(PinManager::class);
    $manager->set(pinUser(), '1234', '1234', null);

    $manager->verify(7, '1234'); // no exception

    expect(SsoUserPin::query()->where('user_id', 7)->first()->failed_attempts)->toBe(0);
});

it('rejects a wrong PIN and counts the attempt', function (): void {
    $manager = app(PinManager::class);
    $manager->set(pinUser(), '1234', '1234', null);

    expect(fn () => $manager->verify(7, '9999'))->toThrow(InvalidPinException::class);

    expect(SsoUserPin::query()->where('user_id', 7)->first()->failed_attempts)->toBe(1);
});

it('locks the PIN after the configured number of failures', function (): void {
    config()->set('sso.pin.max_attempts', 3);
    $manager = app(PinManager::class);
    $manager->set(pinUser(), '1234', '1234', null);

    foreach (range(1, 3) as $_) {
        try {
            $manager->verify(7, '0000');
        } catch (InvalidPinException) {
            // expected
        }
    }

    expect(fn () => $manager->verify(7, '1234'))->toThrow(PinLockedException::class);
});

it('requires the current PIN to change an existing one', function (): void {
    $manager = app(PinManager::class);
    $manager->set(pinUser(), '1234', '1234', null);

    expect(fn () => $manager->set(pinUser(), '5678', '5678', 'wrong'))->toThrow(InvalidPinException::class);

    $manager->set(pinUser(), '5678', '5678', '1234'); // correct current PIN

    $manager->verify(7, '5678'); // new PIN works, no exception
});

it('rejects PINs that fail the format rules', function (): void {
    $manager = app(PinManager::class);

    expect(fn () => $manager->set(pinUser(), '12', '12', null))->toThrow(InvalidPinException::class);
    expect(fn () => $manager->set(pinUser(), '12345', '12345', null))->toThrow(InvalidPinException::class);
    expect(fn () => $manager->set(pinUser(), 'abcd', 'abcd', null))->toThrow(InvalidPinException::class);
});

it('rejects a PIN whose confirmation does not match', function (): void {
    $manager = app(PinManager::class);

    expect(fn () => $manager->set(pinUser(), '1234', '5678', null))->toThrow(InvalidPinException::class);

    expect($manager->has(7))->toBeFalse();
});
