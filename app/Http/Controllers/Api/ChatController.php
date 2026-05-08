<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Chat;
use App\Models\ChatParticipant;

class ChatController extends Controller
{
    // 🔥 GET ALL CHATS (private + group)
    public function index(Request $request)
    {
        $user = $request->user();

        $chats = Chat::whereHas('participants', function ($q) use ($user) {
            $q->where('user_id', $user->id)
              ->where('user_type', $user->role ?? 'employee');
        })
        ->with(['lastMessage', 'participants'])
        ->orderBy('updated_at', 'desc')
        ->get();

        return response()->json($chats);
    }

    // 🔥 GET OR CREATE PRIVATE CHAT
    public function privateChat(Request $request)
    {
        $request->validate([
            'user_id' => 'required'
        ]);

        $authUser = $request->user();
        $otherUser = $request->user_id;

        $chat = Chat::where('type', 'private')
            ->whereHas('participants', function ($q) use ($authUser) {
                $q->where('user_id', $authUser->id);
            })
            ->whereHas('participants', function ($q) use ($otherUser) {
                $q->where('user_id', $otherUser);
            })
            ->first();

        if ($chat) {
            return response()->json($chat);
        }

        $chat = Chat::create([
            'type' => 'private',
            'created_by_id' => $authUser->id,
            'created_by_type' => $authUser->role ?? 'employee'
        ]);

        ChatParticipant::insert([
            [
                'chat_id' => $chat->id,
                'user_id' => $authUser->id,
                'user_type' => $authUser->role ?? 'employee',
                'role' => 'member',
                'joined_at' => now()
            ],
            [
                'chat_id' => $chat->id,
                'user_id' => $otherUser,
                'user_type' => 'employee',
                'role' => 'member',
                'joined_at' => now()
            ]
        ]);

        return response()->json($chat);
    }
}