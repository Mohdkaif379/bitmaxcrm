<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MessageRead extends Model
{
    protected $fillable = [
        'message_id',
        'user_id',
        'user_type',
        'read_at'
    ];

    public function message()
    {
        return $this->belongsTo(Message::class);
    }
}
