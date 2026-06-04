<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TaskManagement extends Model
{
    protected $table = 'task_management';

    protected $fillable = [
        'project_id',
        'task_name',
        'type',
        'priority',
        'start_date',
        'end_date',
        'assigned_to',
        'status',
    ];

    protected $casts = [
        'start_date' => 'date',
        'end_date' => 'date',
    ];

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id');
    }

    public function assignedEmployee(): BelongsTo
    {
        return $this->belongsTo(Employee::class, 'assigned_to');
    }

    public function scopeAssignedToEmployee(Builder $query, int $employeeId): Builder
    {
        return $query->where('assigned_to', $employeeId);
    }
}
