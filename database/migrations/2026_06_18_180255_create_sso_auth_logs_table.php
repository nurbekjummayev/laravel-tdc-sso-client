<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('sso_auth_logs', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable()->index();

            // Links the event to the Passport access token involved (the token
            // minted on login, or the one revoked on logout). Matches the type
            // of oauth_access_tokens.id, which is char(80).
            //
            // Intentionally a plain indexed column WITHOUT a hard foreign key:
            // oauth_access_tokens may live on a different connection
            // (config('passport.connection')) than this log table, and a
            // database-level FK cannot span connections/databases. It is also
            // nullable because not every event carries a token (e.g. a logout
            // when the token was already revoked, or a failed login).
            $table->char('token_id', 80)->nullable()->index();

            $table->string('event', 32)->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('created_at')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sso_auth_logs');
    }
};
