<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ReportSubmission extends Model
{
    protected $fillable = [
        'employee_id',
        'report_status',
    ];
}
