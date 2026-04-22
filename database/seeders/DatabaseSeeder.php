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
            'full_name'     => 'Arman Hossain',
            'email'         => 'admin@gmail.com',
            'password'      => Hash::make('12345678'), // 👈 hashed password
            'number'        => '9027114834',
            'profile_photo' => null,
            'role'          => 'admin',
            'permissions'   => json_encode(['*']),
            'status'        => 1,
            'bio'           => 'i am backend developer',
            'company_logo'  => null,
            'company_name'  => 'Kaif Software Pvt Ltd',
            'created_at'    => now(),
            'updated_at'    => now(),
        ]);
    }
}