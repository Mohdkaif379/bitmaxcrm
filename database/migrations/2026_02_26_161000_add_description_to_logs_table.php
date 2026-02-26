<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (!Schema::hasTable('logs')) {
            return;
        }

        if (!Schema::hasColumn('logs', 'description')) {
            Schema::table('logs', function (Blueprint $table) {
                $table->text('description')->nullable()->after('action');
            });
        }

        if (Schema::hasColumn('logs', 'details') && Schema::hasColumn('logs', 'description')) {
            DB::table('logs')
                ->whereNull('description')
                ->whereNotNull('details')
                ->update(['description' => DB::raw('details')]);
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('logs')) {
            return;
        }

        if (Schema::hasColumn('logs', 'description')) {
            Schema::table('logs', function (Blueprint $table) {
                $table->dropColumn('description');
            });
        }
    }
};

