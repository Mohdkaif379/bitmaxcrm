<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Admin extends Model
{
    protected $casts = [
        'permissions' => 'array',
    ];

    public function createdLeads()
    {
        return $this->hasMany(Lead_Create::class, 'created_by');
    }
}
