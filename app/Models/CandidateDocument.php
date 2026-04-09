<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CandidateDocument extends Model
{
    protected $fillable = [
        'candidate_info_id',
        'pay_slip',
        'reliving_letter',
        'experience_letter',
        'passport_photo',
        'id_proof',
        'address_proof',
        'graduation_certificate',
        '10_certificate',
        '12_certificate',
    ];

    protected $casts = [
        'pay_slip' => 'boolean',
        'reliving_letter' => 'boolean',
        'experience_letter' => 'boolean',
        'passport_photo' => 'boolean',
        'id_proof' => 'boolean',
        'address_proof' => 'boolean',
        'graduation_certificate' => 'boolean',
        '10_certificate' => 'boolean',
        '12_certificate' => 'boolean',
    ];

    public function candidateInfo(): BelongsTo
    {
        return $this->belongsTo(CandidateInfo::class);
    }
}
