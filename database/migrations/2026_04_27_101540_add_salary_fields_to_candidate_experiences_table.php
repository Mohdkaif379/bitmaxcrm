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
        Schema::table('candidate_experiences', function (Blueprint $table) {
            $table->decimal('current_salary', 10, 2)->nullable()->after('city');
            $table->decimal('expected_salary', 10, 2)->nullable()->after('current_salary');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('candidate_experiences', function (Blueprint $table) {
            //
        });
    }
};
