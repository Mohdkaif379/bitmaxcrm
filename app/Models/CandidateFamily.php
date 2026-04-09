<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CandidateFamily extends Model
{
    protected $fillable = [
        'candidate_info_id',
        'father_name',
        'mother_name',
        'occupation',
        'mother_occupation',
        'age',
    ];

    public function candidateInfo(): BelongsTo
    {
        return $this->belongsTo(CandidateInfo::class);
    }
}
