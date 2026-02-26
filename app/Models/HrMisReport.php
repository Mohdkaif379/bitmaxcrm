<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class HrMisReport extends Model
{
    protected $casts = [
        'report_date' => 'date',
        'week_start_date' => 'date',
        'week_end_date' => 'date',
        'salary_disbursement_date' => 'date',
    ];

    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
