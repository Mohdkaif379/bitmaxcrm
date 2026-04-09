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
        Schema::create('candidate_documents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('candidate_info_id')
                ->constrained('candidate_infos')
                ->cascadeOnDelete();
            $table->string('pay_slip')->nullable();
            $table->string('reliving_letter')->nullable();
            $table->string('experience_letter')->nullable();
            $table->string('passport_photo')->nullable();
            $table->string('id_proof')->nullable();
            $table->string('address_proof')->nullable();
            $table->string('graduation_certificate')->nullable();
            $table->string('10_certificate')->nullable();
            $table->string('12_certificate')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('candidate_documents');
    }
};
