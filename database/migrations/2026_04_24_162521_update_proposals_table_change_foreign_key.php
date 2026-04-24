<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('proposals', function (Blueprint $table) {
            
            // 🔴 Old FK remove
            $table->dropForeign(['lead_id']);

            // 🟢 New FK (customers table se)
            $table->foreign('lead_id')
                  ->references('id')
                  ->on('lead_creates')
                  ->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table('proposals', function (Blueprint $table) {
            
            // 🔴 New FK remove
            $table->dropForeign(['lead_id']);

            // 🟢 Old FK wapas (leads table)
            $table->foreign('lead_id')
                  ->references('id')
                  ->on('leads')
                  ->cascadeOnDelete();
        });
    }
};