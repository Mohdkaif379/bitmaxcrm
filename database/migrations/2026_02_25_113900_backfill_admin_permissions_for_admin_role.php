<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        DB::table('admins')
            ->whereRaw('LOWER(role) = ?', ['admin'])
            ->whereNull('permissions')
            ->update(['permissions' => json_encode(['*'])]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        DB::table('admins')
            ->whereRaw('LOWER(role) = ?', ['admin'])
            ->where('permissions', json_encode(['*']))
            ->update(['permissions' => null]);
    }
};
