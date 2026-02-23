<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeeFamilyDetails extends Model
{
    protected $fillable = [
        'employee_id',
        'name',
        'relationship',
        'contact',
        'aadhar_number',
        'aadhar_profile',
        'pan_number',
        'pan_profile',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
