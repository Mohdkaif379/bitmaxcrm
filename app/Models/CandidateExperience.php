<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CandidateExperience extends Model
{
    protected $fillable = [
        'candidate_info_id',
        'company_name',
        'post_held',
        'department',
        'tenure',
        'city',
        'current_salary',
        'expected_salary',
    ];

    public function candidateInfo(): BelongsTo
    {
        return $this->belongsTo(CandidateInfo::class);
    }
}
