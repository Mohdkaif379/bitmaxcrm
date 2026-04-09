<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CandidateAddress extends Model
{
    protected $fillable = [
        'candidate_info_id',
        'address_line1',
        'contact_no',
    ];

    public function candidateInfo(): BelongsTo
    {
        return $this->belongsTo(CandidateInfo::class);
    }
}
