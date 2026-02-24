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

        if (!Schema::hasColumn('salary_slips', 'slip_code')) {
            Schema::table('salary_slips', function (Blueprint $table) {
                $table->string('slip_code', 30)->nullable()->after('id');
            });
        }

        $rows = DB::table('salary_slips')
            ->select('id', 'year')
            ->orderBy('year')
            ->orderBy('id')
            ->get();

        $counters = [];
        foreach ($rows as $row) {
            $year = (int) ($row->year ?? 0);
            if ($year <= 0) {
                $year = (int) date('Y');
            }

            if (!isset($counters[$year])) {
                $counters[$year] = 1;
            }

            $code = sprintf('BT/HR/%d/%04d', $year, $counters[$year]);
            DB::table('salary_slips')->where('id', $row->id)->update(['slip_code' => $code]);
            $counters[$year]++;
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->unique('slip_code');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('salary_slips') || !Schema::hasColumn('salary_slips', 'slip_code')) {
            return;
        }

        Schema::table('salary_slips', function (Blueprint $table) {
            $table->dropUnique('salary_slips_slip_code_unique');
            $table->dropColumn('slip_code');
        });
    }
};
