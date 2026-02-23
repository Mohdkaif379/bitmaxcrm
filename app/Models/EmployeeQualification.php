<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeeQualification extends Model
{
    protected $fillable = [
        'employee_id',
        'degree',
        'institution',
        'passing_year',
        'grade',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
