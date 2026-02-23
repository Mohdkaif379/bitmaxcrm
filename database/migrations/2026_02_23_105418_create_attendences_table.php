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
        Schema::create('attendences', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('employee_id');
            $table->date('date');
            $table->time('mark_in')->nullable();
            $table->time('mark_out')->nullable();
            $table->time('break_start')->nullable();
            $table->time('break_end')->nullable();
            $table->string('profile_image')->nullable();
            $table->enum('status', ['present', 'absent', 'halfday', 'holiday'])->default('present');
            $table->foreign('employee_id')->references('id')->on('employees')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('attendences');
    }
};
