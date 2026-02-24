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
        if (!Schema::hasColumn('activities', 'max_points')) {
            Schema::table('activities', function (Blueprint $table) {
                $table->unsignedInteger('max_points')->default(0)->after('who_can_give_points');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasColumn('activities', 'max_points')) {
            Schema::table('activities', function (Blueprint $table) {
                $table->dropColumn('max_points');
            });
        }
    }
};
