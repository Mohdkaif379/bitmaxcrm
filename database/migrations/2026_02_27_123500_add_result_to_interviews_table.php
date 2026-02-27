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
        if (!Schema::hasTable('interviews')) {
            return;
        }

        if (!Schema::hasColumn('interviews', 'result')) {
            Schema::table('interviews', function (Blueprint $table) {
                $table->string('result')->default('pending')->after('status');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('interviews')) {
            return;
        }

        if (Schema::hasColumn('interviews', 'result')) {
            Schema::table('interviews', function (Blueprint $table) {
                $table->dropColumn('result');
            });
        }
    }
};
