<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Interview extends Model
{
    protected $fillable = [
        'job_profile',
        'scheduled_at',
        'location',
        'candidate_name',
        'candidate_email',
        'candidate_phone',
        'experience',
        'interview_date',
        'interview_time',
        'status',
        'candidate_resume',
        'final_feedback',
    ];

    public function rounds(): HasMany
    {
        return $this->hasMany(InterviewRound::class, 'interview_id');
    }
}
