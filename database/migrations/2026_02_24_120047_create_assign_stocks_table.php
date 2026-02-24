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
        Schema::create('assign_stocks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('employee_id')->constrained('employees')->cascadeOnDelete();
            $table->foreignId('stock_management_id')->constrained('stock_management')->cascadeOnDelete();
            $table->unsignedInteger('assign_quantity')->default(1);
            $table->date('assign_date');
            $table->text('remarks')->nullable();
            $table->index(['employee_id', 'stock_management_id']);
            $table->index('assign_date');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('assign_stocks');
    }
};
