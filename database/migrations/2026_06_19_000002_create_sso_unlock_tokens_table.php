<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Long-lived "unlock" tokens issued at login alongside the session token.
     *
     * Delivered to the SPA as an httpOnly cookie and exchanged (together with
     * the PIN) for a fresh session token after a screen lock. Stored as a fast
     * SHA-256 lookup hash (the token itself is high entropy, so a slow hash is
     * unnecessary and would prevent lookup). Rotated on every use; a presented
     * token that is already revoked signals theft.
     */
    public function up(): void
    {
        Schema::create('sso_unlock_tokens', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();

            // sha256(token) — deterministic so it can be looked up.
            $table->string('token_hash', 64)->unique();

            // Absolute deadline from login. Rotations carry this forward
            // unchanged, so the session can never outlive the hard cap.
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_unlock_tokens');
    }
};
