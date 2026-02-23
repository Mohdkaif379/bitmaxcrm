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
        Schema::create('employee_payrolls', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('employee_id');
            $table->decimal('basic_salary', 10, 2);
            $table->decimal('hra', 10, 2)->nullable();
            $table->decimal('conveyance_allowance', 10, 2)->nullable();
            $table->decimal('medical_allowance', 10, 2)->nullable();
            $table->foreign('employee_id')->references('id')->on('employees')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('employee_payrolls');
    }
};
