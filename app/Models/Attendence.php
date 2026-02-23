<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Attendence extends Model
{
    protected $fillable = [
        'employee_id',
        'date',
        'mark_in',
        'mark_out',
        'break_start',
        'break_end',
        'profile_image',
        'status',
    ];

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }
}
