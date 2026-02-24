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

        if (!Schema::hasColumn('salary_slips', 'deductions')) {
            Schema::table('salary_slips', function (Blueprint $table) {
                $table->json('deductions')->nullable()->after('employee_id');
            });
        }

        if (Schema::hasColumn('salary_slips', 'deduction_type') && Schema::hasColumn('salary_slips', 'amount')) {
            $rows = DB::table('salary_slips')->select('id', 'deduction_type', 'amount', 'deductions')->get();
            foreach ($rows as $row) {
                $existing = json_decode((string) ($row->deductions ?? ''), true);
                if (is_array($existing) && !empty($existing)) {
                    continue;
                }

                $types = json_decode((string) $row->deduction_type, true);
                if (!is_array($types)) {
                    $types = ($row->deduction_type === null || $row->deduction_type === '') ? [] : [(string) $row->deduction_type];
                }

                $amounts = json_decode((string) $row->amount, true);
                if (!is_array($amounts)) {
                    $amounts = ($row->amount === null || $row->amount === '') ? [] : [(float) $row->amount];
                }

                $count = max(count($types), count($amounts));
                $deductions = [];
                for ($i = 0; $i < $count; $i++) {
                    $deductions[] = [
                        'deduction_type' => (string) ($types[$i] ?? 'Deduction'),
                        'amount' => (float) ($amounts[$i] ?? 0),
                    ];
                }

                DB::table('salary_slips')
                    ->where('id', $row->id)
                    ->update([
                        'deductions' => json_encode($deductions, JSON_UNESCAPED_UNICODE),
                    ]);
            }

            Schema::table('salary_slips', function (Blueprint $table) {
                $table->dropColumn(['deduction_type', 'amount']);
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('salary_slips')) {
            return;
        }

        if (Schema::hasColumn('salary_slips', 'deductions')) {
            Schema::table('salary_slips', function (Blueprint $table) {
                $table->json('deduction_type')->nullable()->after('employee_id');
                $table->json('amount')->nullable()->after('deduction_type');
            });

            $rows = DB::table('salary_slips')->select('id', 'deductions')->get();
            foreach ($rows as $row) {
                $deductions = json_decode((string) $row->deductions, true);
                $types = [];
                $amounts = [];
                if (is_array($deductions)) {
                    foreach ($deductions as $item) {
                        if (!is_array($item)) {
                            continue;
                        }

                        $types[] = (string) ($item['deduction_type'] ?? 'Deduction');
                        $amounts[] = (float) ($item['amount'] ?? 0);
                    }
                }

                DB::table('salary_slips')
                    ->where('id', $row->id)
                    ->update([
                        'deduction_type' => json_encode($types, JSON_UNESCAPED_UNICODE),
                        'amount' => json_encode($amounts, JSON_UNESCAPED_UNICODE),
                    ]);
            }

            Schema::table('salary_slips', function (Blueprint $table) {
                $table->dropColumn('deductions');
            });
        }
    }
};
