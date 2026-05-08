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
        Schema::create('messages', function (Blueprint $table) {

    $table->id();

    $table->foreignId('chat_id')
        ->constrained()
        ->onDelete('cascade');

    $table->unsignedBigInteger('sender_id');

    $table->enum('sender_type', ['admin', 'employee']);

    $table->longText('message')->nullable();

    $table->enum('message_type', [
        'text',
        'image',
        'video',
        'audio',
        'file'
    ])->default('text');

    $table->string('file')->nullable();

    $table->string('file_name')->nullable();

    $table->string('mime_type')->nullable();

    $table->string('file_size')->nullable();

    $table->string('thumbnail')->nullable();

    $table->unsignedBigInteger('reply_to')->nullable();

    $table->boolean('is_forwarded')->default(false);

    $table->boolean('is_edited')->default(false);

    $table->boolean('is_deleted')->default(false);

    $table->timestamp('delivered_at')->nullable();

    $table->timestamp('seen_at')->nullable();

    $table->timestamps();
});
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('messages');
    }
};
