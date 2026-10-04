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
        if (Schema::hasColumn('sso_auth_logs', 'meta')) {
            return;
        }

        Schema::table('sso_auth_logs', function (Blueprint $table): void {
            // Free-form event data: the denial reason, plus whatever the host's
            // sso.auth_log.meta_resolver adds (geolocation, device, ...).
            $table->json('meta')->nullable()->after('user_agent');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (! Schema::hasColumn('sso_auth_logs', 'meta')) {
            return;
        }

        Schema::table('sso_auth_logs', function (Blueprint $table): void {
            $table->dropColumn('meta');
        });
    }
};
