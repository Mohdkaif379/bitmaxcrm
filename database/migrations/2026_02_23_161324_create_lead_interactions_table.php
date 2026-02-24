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
        Schema::create('lead_interactions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('lead_id')->constrained('leads')->cascadeOnDelete();
            $table->string('interaction_type', 100);
            $table->text('description')->nullable();
            $table->date('interaction_date');
            $table->string('interaction_status', 100)->default('pending');
            $table->date('next_follow_up_date')->nullable();
            $table->foreignId('created_by')->constrained('admins')->cascadeOnDelete();
            $table->index(['lead_id', 'interaction_date']);
            $table->index('interaction_status');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('lead_interactions');
    }
};
