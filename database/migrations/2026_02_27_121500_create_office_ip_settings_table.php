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
        Schema::create('office_ip_settings', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->unsignedBigInteger('synced_by_admin_id')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();

            $table->foreign('synced_by_admin_id')
                ->references('id')
                ->on('admins')
                ->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('office_ip_settings');
    }
};
