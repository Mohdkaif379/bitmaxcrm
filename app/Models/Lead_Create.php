<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Lead_Create extends Model
{
    protected $table = 'lead_creates';

    protected $fillable = [
        'name',
        'email',
        'phone',
        'company',
        'project_code',
        'date',
        'remarks',
        'project_interested',
        'created_by',
        'status',
        'location',
        'attended_by',
        'is_deleted',
        'deleted_at',
    ];

    protected $casts = [
        'date' => 'date',
        'is_deleted' => 'boolean',
        'deleted_at' => 'datetime',
    ];

 // attended_by -> employees table
    public function attendedBy()
    {
        return $this->belongsTo(Employee::class, 'attended_by');
    }

    // created_by -> admins table
    public function createdBy()
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
