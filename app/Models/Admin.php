<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Admin extends Model
{
    protected $casts = [
        'permissions' => 'array',
    ];

    public function leadCreates(): HasMany
    {
        return $this->hasMany(Lead_Create::class, 'attended_by');
    }
}
