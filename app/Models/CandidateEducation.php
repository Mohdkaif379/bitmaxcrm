<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CandidateEducation extends Model
{
    protected $table = 'candidate_education';

    protected $fillable = [
        'candidate_info_id',
        'qualification',
        'institution',
        'year_of_passing',
        'grade',
        'specialization',
    ];

    public function candidateInfo(): BelongsTo
    {
        return $this->belongsTo(CandidateInfo::class);
    }
}
