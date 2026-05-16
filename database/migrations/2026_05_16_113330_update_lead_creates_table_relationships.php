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
        Schema::table('lead_creates', function (Blueprint $table) {

            // old foreign remove
            $table->dropForeign(['attended_by']);

            // attended_by -> employees table
            $table->foreign('attended_by')
                ->references('id')
                ->on('employees')
                ->nullOnDelete();

            // created_by add as foreign key with admins table
            $table->unsignedBigInteger('created_by')->nullable()->change();

            $table->foreign('created_by')
                ->references('id')
                ->on('admins')
                ->nullOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('lead_creates', function (Blueprint $table) {

            // remove new foreigns
            $table->dropForeign(['attended_by']);
            $table->dropForeign(['created_by']);

            // attended_by back to admins
            $table->foreign('attended_by')
                ->references('id')
                ->on('admins')
                ->nullOnDelete();
        });
    }
};