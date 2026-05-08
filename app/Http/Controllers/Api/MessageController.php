<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Message;
use App\Models\Chat;
use App\Models\ChatParticipant;
use App\Services\AblyService;

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
        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        $role = $user->role ?? 'employee';

        // check participant exists
        $participant = ChatParticipant::where('chat_id', $request->chat_id)
            ->where('user_id', $user->id)
            ->where('user_type', $role)
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
            'sender_type' => $role,
            'message' => $request->message,
            'message_type' => $request->message_type ?? 'text'
        ]);

        // update last message
        Chat::where('id', $request->chat_id)
            ->update([
                'last_message_id' => $message->id
            ]);

        // 🔥 PUBLISH TO ABLY - Real-time delivery
        try {
            $ably = new AblyService();
            $ably->publishMessage($request->chat_id, [
                'id' => $message->id,
                'chat_id' => $message->chat_id,
                'sender_id' => $message->sender_id,
                'sender_type' => $message->sender_type,
                'sender_name' => $user->full_name ?? $user->emp_name ?? 'Unknown',
                'message' => $message->message,
                'message_type' => $message->message_type,
                'created_at' => $message->created_at->toISOString()
            ]);

            // Notify all participants (except sender)
            $participants = ChatParticipant::where('chat_id', $request->chat_id)
                ->where(function ($q) use ($user, $role) {
                    $q->where('user_id', '!=', $user->id)
                      ->orWhere('user_type', '!=', $role);
                })
                ->get();

            foreach ($participants as $p) {
                $ably->publishToUser($p->user_id, $p->user_type, [
                    'type' => 'new_message',
                    'chat_id' => $request->chat_id,
                    'message_id' => $message->id,
                    'sender_name' => $user->full_name ?? $user->emp_name ?? 'Unknown',
                    'preview' => \Illuminate\Support\Str::limit($message->message, 50)
                ]);
            }
        } catch (\Exception $e) {
            // Log error but don't fail the API response
            \Illuminate\Support\Facades\Log::error('Ably publish failed: ' . $e->getMessage());
        }

        return response()->json([
            'status' => true,
            'message' => 'Message sent successfully',
            'data' => $message
        ]);
    }

    // 🔥 GET CHAT MESSAGES
    public function list(Request $request, $chatId)
    {
        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        $role = $user->role ?? 'employee';

        // check participant
        $participant = ChatParticipant::where('chat_id', $chatId)
            ->where('user_id', $user->id)
            ->where('user_type', $role)
            ->first();

        if (!$participant) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized access'
            ], 403);
        }

        $messages = Message::where('chat_id', $chatId)
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

        $user = $request->user() ?? $request->auth_admin;

        $message = Message::find($request->message_id);

        $message->seen_at = now();
        $message->save();

        // 🔥 PUBLISH READ RECEIPT TO ABLY
        try {
            $ably = new AblyService();
            $ably->publishReadReceipt($message->chat_id, [
                'message_id' => $message->id,
                'read_by' => $user ? $user->id : null,
                'read_at' => now()->toISOString()
            ]);
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::error('Ably read receipt failed: ' . $e->getMessage());
        }

        return response()->json([
            'status' => true,
            'message' => 'Message marked as read'
        ]);
    }

    // 🔥 TYPING INDICATOR
    public function typing(Request $request)
    {
        $request->validate([
            'chat_id' => 'required|exists:chats,id'
        ]);

        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        try {
            $ably = new AblyService();
            $ably->publishTyping($request->chat_id, [
                'user_id' => $user->id,
                'user_type' => $user->role ?? 'employee',
                'user_name' => $user->full_name ?? $user->emp_name ?? 'Unknown'
            ]);
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::error('Ably typing failed: ' . $e->getMessage());
        }

        return response()->json([
            'status' => true,
            'message' => 'Typing event sent'
        ]);
    }

    // 🔥 STOP TYPING INDICATOR
    public function stopTyping(Request $request)
    {
        $request->validate([
            'chat_id' => 'required|exists:chats,id'
        ]);

        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        try {
            $ably = new AblyService();
            $ably->publishStopTyping($request->chat_id, [
                'user_id' => $user->id,
                'user_type' => $user->role ?? 'employee'
            ]);
        } catch (\Exception $e) {
            \Illuminate\Support\Facades\Log::error('Ably stop-typing failed: ' . $e->getMessage());
        }

        return response()->json([
            'status' => true,
            'message' => 'Stop typing event sent'
        ]);
    }
}