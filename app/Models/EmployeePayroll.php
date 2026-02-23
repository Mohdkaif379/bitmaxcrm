<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeePayroll extends Model
{
    protected $fillable = [
        'employee_id',
        'basic_salary',
        'hra',
        'conveyance_allowance',
        'medical_allowance',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
