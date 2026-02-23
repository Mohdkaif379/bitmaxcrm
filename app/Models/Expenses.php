<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Expenses extends Model
{
    protected $fillable = [
        'title',
        'category',
        'amount',
        'date',
        'created_by',
    ];

    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
