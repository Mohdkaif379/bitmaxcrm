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
        Schema::create('member_assigns', function (Blueprint $table) {
            $table->id();
            $table->foreignId('tl_id')->constrained('employees')->cascadeOnDelete();
            $table->foreignId('employee_id')->constrained('employees')->cascadeOnDelete();
            $table->foreignId('assigned_by')->nullable()->constrained('admins')->nullOnDelete();
            $table->timestamps();

            $table->unique('employee_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('member_assigns');
    }
};
