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
        Schema::create('employees', function (Blueprint $table) {
            $table->id();
            $table->string('emp_code')->unique();
            $table->string('emp_name');
            $table->string('emp_email')->unique();
            $table->string('emp_phone')->nullable();
            $table->string('joining_date')->nullable();
            $table->string('dob')->nullable();
            $table->string('position')->nullable();
            $table->string('department')->nullable();
            $table->string('status')->default('active');
            $table->string('role')->default('employee');
            $table->string('profile_photo')->nullable();
            $table->string('password');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('employees');
    }
};
