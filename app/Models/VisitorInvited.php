<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class VisitorInvited extends Model
{
    protected $fillable = [
        'name',
        'email',
        'phone',
        'contact_person_name',
        'contact_person_phone',
        'purpose',
        'visit_date',
        'invite_code',
    ];

    protected $casts = [
        'visit_date' => 'datetime',
    ];
}
