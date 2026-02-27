<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OfficeIpSetting extends Model
{
    protected $fillable = [
        'ip_address',
        'synced_by_admin_id',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    public function syncedByAdmin(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'synced_by_admin_id');
    }
}
