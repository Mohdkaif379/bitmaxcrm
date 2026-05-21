<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    protected $fillable = [
        'project_code',
        'title',
        'deadline',
        'status',
        'tl_id',
    ];

    public function tl()
    {
        return $this->belongsTo(Employee::class, 'tl_id');
    }
}
