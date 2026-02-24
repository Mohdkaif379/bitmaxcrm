<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Activity extends Model
{
    protected $casts = [
        'employee_ids' => 'array',
    ];
}
