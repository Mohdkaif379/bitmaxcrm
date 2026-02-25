<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Employee extends Model
{
    protected $fillable = [
        'emp_code',
        'emp_name',
        'emp_email',
        'emp_phone',
        'joining_date',
        'dob',
        'position',
        'department',
        'status',
        'role',
        'profile_photo',
        'password',
    ];

    public function familyDetails(): HasMany
    {
        return $this->hasMany(EmployeeFamilyDetails::class, 'employee_id');
    }

    public function bankDetails(): HasMany
    {
        return $this->hasMany(EmployeeBankDetails::class, 'employee_id');
    }

    public function payrolls(): HasMany
    {
        return $this->hasMany(EmployeePayroll::class, 'employee_id');
    }

    public function qualifications(): HasMany
    {
        return $this->hasMany(EmployeeQualification::class, 'employee_id');
    }

    public function addresses(): HasMany
    {
        return $this->hasMany(EmployeeAddress::class, 'employee_id');
    }

    public function documents(): HasMany
    {
        return $this->hasMany(EmployeeDocuments::class, 'employee_id');
    }

    public function experiences(): HasMany
    {
        return $this->hasMany(EmployeeExperience::class, 'employee_id');
    }

    public function tasks(): BelongsToMany
    {
        return $this->belongsToMany(Task::class, 'employee_task', 'employee_id', 'task_id')
            ->withTimestamps();
    }
}
