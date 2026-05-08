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
       Schema::create('chat_participants', function (Blueprint $table) {

    $table->id();

    $table->foreignId('chat_id')
        ->constrained()
        ->onDelete('cascade');

    $table->unsignedBigInteger('user_id');

    $table->enum('user_type', ['admin', 'employee']);

    $table->enum('role', ['admin', 'member'])
        ->default('member');

    $table->boolean('is_muted')->default(false);

    $table->boolean('is_pinned')->default(false);

    $table->boolean('left_group')->default(false);

    $table->timestamp('joined_at')->nullable();

    $table->timestamps();
});
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('chat_participants');
    }
};
