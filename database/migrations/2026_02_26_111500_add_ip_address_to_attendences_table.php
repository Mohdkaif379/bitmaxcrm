<?php

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
        if (!Schema::hasTable('attendences')) {
            return;
        }

        Schema::table('attendences', function (Blueprint $table) {
            if (!Schema::hasColumn('attendences', 'ip_address')) {
                $table->string('ip_address', 45)->nullable()->after('profile_image');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('attendences')) {
            return;
        }

        Schema::table('attendences', function (Blueprint $table) {
            if (Schema::hasColumn('attendences', 'ip_address')) {
                $table->dropColumn('ip_address');
            }
        });
    }
};

