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
        if (!Schema::hasTable('salary_slips')) {
            return;
        }

        if (!Schema::hasColumn('salary_slips', 'month')) {
            return;
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->string('month_tmp', 20)->nullable()->after('deductions');
        });

        $map = [
            '1' => 'january',
            '2' => 'february',
            '3' => 'march',
            '4' => 'april',
            '5' => 'may',
            '6' => 'june',
            '7' => 'july',
            '8' => 'august',
            '9' => 'september',
            '10' => 'october',
            '11' => 'november',
            '12' => 'december',
        ];

        $rows = DB::table('salary_slips')->select('id', 'month')->get();
        foreach ($rows as $row) {
            $raw = strtolower(trim((string) $row->month));
            $monthName = $map[$raw] ?? $raw;

            DB::table('salary_slips')
                ->where('id', $row->id)
                ->update(['month_tmp' => $monthName]);
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->dropColumn('month');
        });

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->renameColumn('month_tmp', 'month');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('salary_slips') || !Schema::hasColumn('salary_slips', 'month')) {
            return;
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->unsignedTinyInteger('month_tmp')->nullable()->after('deductions');
        });

        $map = [
            'january' => 1,
            'february' => 2,
            'march' => 3,
            'april' => 4,
            'may' => 5,
            'june' => 6,
            'july' => 7,
            'august' => 8,
            'september' => 9,
            'october' => 10,
            'november' => 11,
            'december' => 12,
        ];

        $rows = DB::table('salary_slips')->select('id', 'month')->get();
        foreach ($rows as $row) {
            $raw = strtolower(trim((string) $row->month));
            $monthNumber = $map[$raw] ?? null;

            DB::table('salary_slips')
                ->where('id', $row->id)
                ->update(['month_tmp' => $monthNumber]);
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->dropColumn('month');
        });

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->renameColumn('month_tmp', 'month');
        });
    }
};
