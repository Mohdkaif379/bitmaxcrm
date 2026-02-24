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
        Schema::create('proposals', function (Blueprint $table) {
            $table->id();
            $table->foreignId('lead_id')->constrained('leads')->cascadeOnDelete();
            $table->decimal('proposal_amount', 15, 2);
            $table->enum('proposal_status', ['sent', 'rejected', 'approved'])->default('sent');
            $table->string('proposal_code', 100)->unique();
            $table->string('file')->nullable();
            $table->index(['lead_id', 'proposal_status']);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('proposals');
    }
};
