<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        DB::table('admins')->insert([
            'full_name'     => 'Admin',
            'email'         => 'admin@gmail.com',
            'password'      => Hash::make('12345678'),
            'number'        => '9027114840',
            'profile_photo' => null,
            'role'          => 'admin',
            'permissions'   => json_encode(['*']),
            'status'        => 1,
            'bio'           => 'I am the admin of this application.',
            'company_logo'  => null,
            'company_name'  => 'Bitmax Technology Pvt. Ltd.',
            'created_at'    => now(),
            'updated_at'    => now(),
        ]);
    }
}