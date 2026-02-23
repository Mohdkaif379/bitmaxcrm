<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeeExperience extends Model
{
    protected $fillable = [
        'employee_id',
        'company_name',
        'position',
        'start_date',
        'end_date',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
