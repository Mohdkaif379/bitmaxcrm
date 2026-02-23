<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeeAddress extends Model
{
    protected $fillable = [
        'employee_id',
        'address_type',
        'street_address',
        'city',
        'state',
        'postal_code',
        'country',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
