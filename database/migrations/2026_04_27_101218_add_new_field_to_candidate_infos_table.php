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
        Schema::table('candidate_infos', function (Blueprint $table) {
            $table->unsignedBigInteger('conducted_by')->nullable()->after('signature');
            $table->foreign('conducted_by')
                ->references('id')
                ->on('employees')
                ->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('candidate_infos', function (Blueprint $table) {
            //
        });
    }
};
