<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ChatParticipant extends Model
{
    protected $fillable = [
        'chat_id',
        'user_id',
        'user_type',
        'role',
        'is_muted',
        'is_pinned',
        'left_group',
        'joined_at'
    ];

    public function chat()
    {
        return $this->belongsTo(Chat::class);
    }

    public function user()
    {
        if ($this->user_type === 'admin') {
            return $this->belongsTo(Admin::class, 'user_id');
        }

        return $this->belongsTo(Employee::class, 'user_id');
    }
}
