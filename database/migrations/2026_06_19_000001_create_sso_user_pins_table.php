<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The screen-lock PIN, kept in its own table (never on the users table).
     * One row per user; the hash, when it was set/changed, and the IP / user
     * agent of the last change are tracked here.
     */
    public function up(): void
    {
        Schema::create('sso_user_pins', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->unique();

            // bcrypt hash of the PIN — never stored in clear text.
            $table->string('pin_hash');

            // Brute-force protection: consecutive failed unlocks and, once the
            // threshold is hit, the time until the PIN is usable again.
            $table->unsignedTinyInteger('failed_attempts')->default(0);
            $table->timestamp('locked_until')->nullable();

            // Context of the last set/change, for auditing.
            $table->string('last_ip', 45)->nullable();
            $table->text('last_user_agent')->nullable();

            // created_at = first set, updated_at = last change.
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sso_user_pins');
    }
};
