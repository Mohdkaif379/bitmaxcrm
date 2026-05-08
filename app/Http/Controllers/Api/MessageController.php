<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Message;
use App\Models\Chat;
use App\Models\ChatParticipant;

class MessageController extends Controller
{
    // 🔥 SEND MESSAGE
    public function send(Request $request)
    {
        $request->validate([
            'chat_id' => 'required|exists:chats,id',
            'message' => 'nullable|string',
            'message_type' => 'nullable|string'
        ]);

        // authenticated user from middleware
        $user = $request->auth_admin;

        // check participant exists
        $participant = ChatParticipant::where('chat_id', $request->chat_id)
            ->where('user_id', $user->id)
            ->where('user_type', $user->role)
            ->first();

        if (!$participant) {
            return response()->json([
                'status' => false,
                'message' => 'You are not participant of this chat'
            ], 403);
        }

        // create message
        $message = Message::create([
            'chat_id' => $request->chat_id,
            'sender_id' => $user->id,
            'sender_type' => $user->role,
            'message' => $request->message,
            'message_type' => $request->message_type ?? 'text'
        ]);

        // update last message
        Chat::where('id', $request->chat_id)
            ->update([
                'last_message_id' => $message->id
            ]);

        return response()->json([
            'status' => true,
            'message' => 'Message sent successfully',
            'data' => $message
        ]);
    }

    // 🔥 GET CHAT MESSAGES
    public function list(Request $request, $chatId)
    {
        $user = $request->auth_admin;

        // check participant
        $participant = ChatParticipant::where('chat_id', $chatId)
            ->where('user_id', $user->id)
            ->where('user_type', $user->role)
            ->first();

        if (!$participant) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized access'
            ], 403);
        }

        $messages = Message::where('chat_id', $chatId)
            ->with('sender')
            ->orderBy('id', 'asc')
            ->get();

        return response()->json([
            'status' => true,
            'data' => $messages
        ]);
    }

    // 🔥 MARK AS READ
    public function markRead(Request $request)
    {
        $request->validate([
            'message_id' => 'required|exists:messages,id'
        ]);

        $message = Message::find($request->message_id);

        $message->seen_at = now();
        $message->save();

        return response()->json([
            'status' => true,
            'message' => 'Message marked as read'
        ]);
    }
}