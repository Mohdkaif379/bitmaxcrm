<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class EmployeeDocuments extends Model
{
    protected $fillable = [
        'employee_id',
        'document_type',
        'file',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
