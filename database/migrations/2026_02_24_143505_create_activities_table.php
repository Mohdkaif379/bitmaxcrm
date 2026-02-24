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
        Schema::create('activities', function (Blueprint $table) {
            $table->id();
            $table->string('title');
            $table->foreignId('employee_id')->constrained('employees')->cascadeOnDelete();
            $table->json('employee_ids')->nullable();
            $table->text('description')->nullable();
            $table->dateTime('date_time');
            $table->enum('status', ['pending', 'active', 'completed'])->default('pending');
            $table->string('who_can_give_points')->nullable();
            $table->unsignedInteger('max_points')->default(0);
            $table->index('status');
            $table->index('date_time');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('activities');
    }
};
