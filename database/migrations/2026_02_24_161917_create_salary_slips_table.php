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
        Schema::create('salary_slips', function (Blueprint $table) {
            $table->id();
            $table->string('slip_code', 30)->unique();
            $table->foreignId('employee_id')->constrained('employees')->cascadeOnDelete();
            $table->json('deductions');
            $table->string('month', 20);
            $table->unsignedSmallInteger('year');
            $table->foreignId('generated_by')->constrained('admins')->cascadeOnDelete();
            $table->index(['employee_id', 'year', 'month']);
            $table->timestamps();
        });
    }

    
    public function down(): void
    {
        Schema::dropIfExists('salary_slips');
    }
};
