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
        if (!Schema::hasColumn('activities', 'employee_ids')) {
            Schema::table('activities', function (Blueprint $table) {
                $table->json('employee_ids')->nullable()->after('employee_id');
            });
        }

        DB::statement("UPDATE activities SET employee_ids = JSON_ARRAY(employee_id) WHERE employee_ids IS NULL");
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasColumn('activities', 'employee_ids')) {
            Schema::table('activities', function (Blueprint $table) {
                $table->dropColumn('employee_ids');
            });
        }
    }
};
