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
        if (!Schema::hasTable('leave_management')) {
            return;
        }

        Schema::table('leave_management', function (Blueprint $table) {
            if (!Schema::hasColumn('leave_management', 'approved_by')) {
                $table->unsignedBigInteger('approved_by')->nullable()->after('file');
                $table->foreign('approved_by')->references('id')->on('admins')->nullOnDelete();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (!Schema::hasTable('leave_management')) {
            return;
        }

        Schema::table('leave_management', function (Blueprint $table) {
            if (Schema::hasColumn('leave_management', 'approved_by')) {
                $table->dropForeign(['approved_by']);
                $table->dropColumn('approved_by');
            }
        });
    }
};

