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
        if (!Schema::hasTable('attendences')) {
            return;
        }

        Schema::table('attendences', function (Blueprint $table) {
            if (!Schema::hasColumn('attendences', 'first_mark_in')) {
                $table->time('first_mark_in')->nullable()->after('mark_in');
            }
            if (!Schema::hasColumn('attendences', 'first_mark_out')) {
                $table->time('first_mark_out')->nullable()->after('mark_out');
            }
            if (!Schema::hasColumn('attendences', 'first_break_start')) {
                $table->time('first_break_start')->nullable()->after('break_start');
            }
            if (!Schema::hasColumn('attendences', 'first_break_end')) {
                $table->time('first_break_end')->nullable()->after('break_end');
            }
        });

        DB::table('attendences')
            ->whereNull('first_mark_in')
            ->update(['first_mark_in' => DB::raw('mark_in')]);

        DB::table('attendences')
            ->whereNull('first_mark_out')
            ->update(['first_mark_out' => DB::raw('mark_out')]);

        DB::table('attendences')
            ->whereNull('first_break_start')
            ->update(['first_break_start' => DB::raw('break_start')]);

        DB::table('attendences')
            ->whereNull('first_break_end')
            ->update(['first_break_end' => DB::raw('break_end')]);
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
            $columnsToDrop = [];

            if (Schema::hasColumn('attendences', 'first_mark_in')) {
                $columnsToDrop[] = 'first_mark_in';
            }
            if (Schema::hasColumn('attendences', 'first_mark_out')) {
                $columnsToDrop[] = 'first_mark_out';
            }
            if (Schema::hasColumn('attendences', 'first_break_start')) {
                $columnsToDrop[] = 'first_break_start';
            }
            if (Schema::hasColumn('attendences', 'first_break_end')) {
                $columnsToDrop[] = 'first_break_end';
            }

            if (!empty($columnsToDrop)) {
                $table->dropColumn($columnsToDrop);
            }
        });
    }
};
