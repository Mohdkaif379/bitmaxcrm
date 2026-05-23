<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MemberAssign extends Model
{
    protected $fillable = [
        'tl_id',
        'employee_id',
        'assigned_by',
    ];

    public function tl(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'tl_id');
    }

    public function employee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'employee_id');
    }

    public function assignedBy(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'assigned_by');
    }
}
