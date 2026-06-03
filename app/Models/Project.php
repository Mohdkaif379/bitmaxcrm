<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Project extends Model
{
    protected $fillable = [
        'project_code',
        'title',
        'deadline',
        'status',
        'tl_id',
    ];

    public function tl(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'tl_id');
    }

    public function taskManagements(): HasMany
    {
        return $this->hasMany(TaskManagement::class, 'project_id');
    }
}
