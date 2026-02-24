<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SalarySlip extends Model
{
    protected $casts = [
        'deductions' => 'array',
        'month' => 'string',
        'year' => 'integer',
    ];
}
