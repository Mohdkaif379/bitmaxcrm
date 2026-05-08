<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Message extends Model
{
    protected $fillable = [
        'chat_id',
        'sender_id',
        'sender_type',
        'message',
        'message_type',
        'file',
        'file_name',
        'mime_type',
        'file_size',
        'thumbnail',
        'reply_to',
        'is_forwarded',
        'is_edited',
        'is_deleted',
        'delivered_at',
        'seen_at'
    ];

    public function chat()
    {
        return $this->belongsTo(Chat::class);
    }

    public function sender()
    {
        if ($this->sender_type === 'admin') {
            return $this->belongsTo(Admin::class, 'sender_id');
        }

        return $this->belongsTo(Employee::class, 'sender_id');
    }

    public function reply()
    {
        return $this->belongsTo(Message::class, 'reply_to');
    }
}
