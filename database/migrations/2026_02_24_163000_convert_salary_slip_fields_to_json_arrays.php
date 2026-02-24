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

                $deductionValue = $row->deduction_type;
                $amountValue = $row->amount;

                $deductionArray = json_decode((string) $deductionValue, true);
                if (!is_array($deductionArray)) {
                    $deductionArray = ($deductionValue === null || $deductionValue === '') ? [] : [(string) $deductionValue];
                }

                $amountArray = json_decode((string) $amountValue, true);
                if (!is_array($amountArray)) {
                    $amountArray = ($amountValue === null || $amountValue === '') ? [] : [(float) $amountValue];
                }

                $count = max(count($deductionArray), count($amountArray));
                $deductions = [];
                for ($index = 0; $index < $count; $index++) {
                    $type = $deductionArray[$index] ?? null;
                    $amt = $amountArray[$index] ?? 0;
                    if ($type === null || $type === '') {
                        $type = 'Deduction';
                    }

                    $deductions[] = [
                        'deduction_type' => (string) $type,
                        'amount' => (float) $amt,
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
                $deductionTypes = [];
                $amounts = [];
                if (is_array($deductions)) {
                    foreach ($deductions as $item) {
                        if (!is_array($item)) {
                            continue;
                        }

                        $deductionTypes[] = (string) ($item['deduction_type'] ?? 'Deduction');
                        $amounts[] = (float) ($item['amount'] ?? 0);
                    }
                }

                DB::table('salary_slips')
                    ->where('id', $row->id)
                    ->update([
                        'deduction_type' => json_encode($deductionTypes, JSON_UNESCAPED_UNICODE),
                        'amount' => json_encode($amounts, JSON_UNESCAPED_UNICODE),
                    ]);
            }

            Schema::table('salary_slips', function (Blueprint $table) {
                $table->dropColumn('deductions');
            });
        }
    }
};
