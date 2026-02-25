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
        Schema::create('conveyance_details', function (Blueprint $table) {
            $table->id();
            $table->foreignId('tour_conveyance_form_id')
                ->constrained('tour_conveyance_forms')
                ->cascadeOnUpdate()
                ->cascadeOnDelete();

            $table->date('travel_date');
            $table->string('mode', 50);
            $table->string('from_location')->nullable();
            $table->string('to_location')->nullable();
            $table->decimal('distance', 10, 2)->default(0.00);
            $table->decimal('amount', 12, 2)->default(0.00);
            $table->timestamps();

            $table->index(['tour_conveyance_form_id', 'travel_date']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('conveyance_details');
    }
};
