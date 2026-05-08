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
        Schema::create('message_reads', function (Blueprint $table) {

    $table->id();

    $table->foreignId('message_id')
        ->constrained()
        ->onDelete('cascade');

    $table->unsignedBigInteger('user_id');

    $table->enum('user_type', ['admin', 'employee']);

    $table->timestamp('read_at');

    $table->timestamps();
});
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('message_reads');
    }
};
