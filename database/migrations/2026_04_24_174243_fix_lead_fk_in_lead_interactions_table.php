<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('lead_interactions', function (Blueprint $table) {

            // 🔴 Old FK remove (wrong table)
            $table->dropForeign(['lead_id']);

            // 🟢 New FK (apni actual lead table ka naam daalo)
            $table->foreign('lead_id')
                  ->references('id')
                  ->on('lead_creates') // 👈 yahan apni table ka exact naam daalna
                  ->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table('lead_interactions', function (Blueprint $table) {

            $table->dropForeign(['lead_id']);

            $table->foreign('lead_id')
                  ->references('id')
                  ->on('leads');
        });
    }
};