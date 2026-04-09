<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class CandidateInfo extends Model
{
    protected $fillable = [
        'full_name',
        'email',
        'phone',
        'dob',
        'blood_group',
        'age',
        'height',
        'weight',
        'disability',
        'marital_status',
        'nationality',
        'religion',
        'hobbies',
        'birth_place',
        'date',
        'place',
        'signature',
    ];

    public function educations(): HasMany
    {
        return $this->hasMany(CandidateEducation::class);
    }

    public function experiences(): HasMany
    {
        return $this->hasMany(CandidateExperience::class);
    }

    public function address(): HasOne
    {
        return $this->hasOne(CandidateAddress::class);
    }

    public function family(): HasOne
    {
        return $this->hasOne(CandidateFamily::class);
    }

    public function document(): HasOne
    {
        return $this->hasOne(CandidateDocument::class);
    }
}
