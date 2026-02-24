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
        Schema::create('stock_management', function (Blueprint $table) {
            $table->id();
            $table->string('item_name', 255);
            $table->text('description');
            $table->unsignedInteger('quantity')->default(0);
            $table->decimal('price', 10, 2);
            $table->string('unit')->nullable();
            $table->decimal('total_price', 12, 2)->default(0);
            $table->index('item_name');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('stock_management');
    }
};
