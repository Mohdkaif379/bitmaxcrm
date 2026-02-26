<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (!Schema::hasTable('report_submissions') || !Schema::hasColumn('report_submissions', 'report_status')) {
            return;
        }

        DB::statement("
            UPDATE report_submissions
            SET report_status = CASE
                WHEN report_status IN ('1', 1, 'yes') THEN 'yes'
                ELSE 'no'
            END
        ");

        DB::statement("ALTER TABLE report_submissions MODIFY report_status ENUM('yes', 'no') NOT NULL DEFAULT 'no'");
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('report_submissions') || !Schema::hasColumn('report_submissions', 'report_status')) {
            return;
        }

        DB::statement("
            UPDATE report_submissions
            SET report_status = CASE
                WHEN report_status = 'yes' THEN 1
                ELSE 0
            END
        ");

        DB::statement("ALTER TABLE report_submissions MODIFY report_status TINYINT(1) NOT NULL DEFAULT 0");
    }
};

