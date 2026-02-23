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
        Schema::create('employee_family_details', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('employee_id');
            $table->string('name');
            $table->string('relationship');
            $table->string('contact')->nullable();
            $table->string('aadhar_number')->nullable();
            $table->string('aadhar_profile')->nullable();
            $table->string('pan_number')->nullable();
            $table->string('pan_profile')->nullable();
            $table->foreign('employee_id')->references('id')->on('employees')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('employee_family_details');
    }
};
