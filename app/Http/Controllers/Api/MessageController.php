<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Message;
use App\Models\Chat;
use App\Models\ChatParticipant;
use App\Services\AblyService;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Illuminate\Support\Facades\Http;

class MessageController extends Controller
{
    // 🔥 SEND MESSAGE
    // public function send(Request $request)
    // {
    //     $request->validate([
    //         'chat_id' => 'required|exists:chats,id',
    //         'message' => 'nullable|string',
    //         'message_type' => 'nullable|string'
    //     ]);

    //     // authenticated user from middleware
    //     $user = $request->user() ?? $request->auth_admin;

    //     if (!$user) {
    //         return response()->json([
    //             'status' => false,
    //             'message' => 'Unauthenticated'
    //         ], 401);
    //     }

    //     $role = $user->role ?? 'employee';

    //     // check participant exists
    //     $participant = ChatParticipant::where('chat_id', $request->chat_id)
    //         ->where('user_id', $user->id)
    //         ->where('user_type', $role)
    //         ->first();

    //     if (!$participant) {
    //         return response()->json([
    //             'status' => false,
    //             'message' => 'You are not participant of this chat'
    //         ], 403);
    //     }

    //     // create message
    //     $message = Message::create([
    //         'chat_id' => $request->chat_id,
    //         'sender_id' => $user->id,
    //         'sender_type' => $role,
    //         'message' => $request->message,
    //         'message_type' => $request->message_type ?? 'text'
    //     ]);

    //     // update last message
    //     Chat::where('id', $request->chat_id)
    //         ->update([
    //             'last_message_id' => $message->id
    //         ]);

    //     // 🔥 PUBLISH TO ABLY - Real-time delivery
    //     try {
    //         $ably = new AblyService();
    //         $ably->publishMessage($request->chat_id, [
    //             'id' => $message->id,
    //             'chat_id' => $message->chat_id,
    //             'sender_id' => $message->sender_id,
    //             'sender_type' => $message->sender_type,
    //             'sender_name' => $user->full_name ?? $user->emp_name ?? 'Unknown',
    //             'message' => $message->message,
    //             'message_type' => $message->message_type,
    //             'created_at' => $message->created_at->toISOString()
    //         ]);

    //         // Notify all participants (except sender)
    //         $participants = ChatParticipant::where('chat_id', $request->chat_id)
    //             ->where(function ($q) use ($user, $role) {
    //                 $q->where('user_id', '!=', $user->id)
    //                   ->orWhere('user_type', '!=', $role);
    //             })
    //             ->get();

    //         foreach ($participants as $p) {
    //             $ably->publishToUser($p->user_id, $p->user_type, [
    //                 'type' => 'new_message',
    //                 'chat_id' => $request->chat_id,
    //                 'message_id' => $message->id,
    //                 'sender_name' => $user->full_name ?? $user->emp_name ?? 'Unknown',
    //                 'preview' => \Illuminate\Support\Str::limit($message->message, 50)
    //             ]);
    //         }
    //     } catch (\Exception $e) {
    //         // Log error but don't fail the API response
    //         \Illuminate\Support\Facades\Log::error('Ably publish failed: ' . $e->getMessage());
    //     }

    //     return response()->json([
    //         'status' => true,
    //         'message' => 'Message sent successfully',
    //         'data' => $message
    //     ]);
    // }


 public function send(Request $request)
{
    $request->validate([
        'chat_id' => 'required|exists:chats,id',
        'message' => 'nullable|string',
        'message_type' => 'nullable|string',
        'file' => 'nullable|file|max:10240',
        'reply_to' => 'nullable|exists:messages,id'
    ]);

    // auth user
    $user = $request->user() ?? $request->auth_admin;

    if (!$user) {
        return response()->json([
            'status' => false,
            'message' => 'Unauthenticated'
        ], 401);
    }

    $role = $user->role ?? 'employee';

    // check participant
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

    /* =========================
        FILE UPLOAD
    ========================= */

    $filePath = null;
    $fileName = null;
    $mimeType = null;
    $fileSize = null;

    if ($request->hasFile('file')) {

        $file = $request->file('file');

        $fileName = time() . '_' . uniqid() . '.' . $file->getClientOriginalExtension();

        $filePath = $file->storeAs('chat_files', $fileName, 'public');

        $mimeType = $file->getMimeType();

        $fileSize = $file->getSize();
    }

    /* =========================
        CREATE MESSAGE
    ========================= */

    $message = Message::create([
        'chat_id' => $request->chat_id,
        'sender_id' => $user->id,
        'sender_type' => $role,

        'message' => $request->message,

        'message_type' => $request->message_type ?? ($filePath ? 'file' : 'text'),

        'file' => $filePath,
        'file_name' => $fileName,
        'mime_type' => $mimeType,
        'file_size' => $fileSize,

        'reply_to' => $request->reply_to,

        'is_forwarded' => false,
        'is_edited' => false,
        'is_deleted' => false,
    ]);

    /* =========================
        UPDATE LAST MESSAGE
    ========================= */

    Chat::where('id', $request->chat_id)
        ->update([
            'last_message_id' => $message->id
        ]);

    $fileUrl = $filePath
        ? asset('storage/' . $filePath)
        : null;

    /* =========================
        REPLY MESSAGE DATA
    ========================= */

    $replyMessage = null;

    if ($message->reply_to) {

        $replyMessage = Message::select(
                'id',
                'message',
                'sender_id',
                'sender_type',
                'message_type'
            )
            ->find($message->reply_to);
    }

    /* =========================
        ABLY REALTIME
    ========================= */

    try {

        $ably = new AblyService();

        // realtime message broadcast
        $ably->publishMessage($request->chat_id, [

            'id' => $message->id,
            'chat_id' => $message->chat_id,

            'sender_id' => $message->sender_id,
            'sender_type' => $message->sender_type,

            'sender_name' => $user->full_name
                ?? $user->emp_name
                ?? 'Unknown',

            'message' => $message->message,
            'message_type' => $message->message_type,

            'file_url' => $fileUrl,
            'file_name' => $message->file_name,
            'mime_type' => $message->mime_type,
            'file_size' => $message->file_size,

            'reply_to' => $message->reply_to,
            'reply_message' => $replyMessage,

            'is_edited' => $message->is_edited,
            'is_deleted' => $message->is_deleted,

            'created_at' => $message->created_at->toISOString()
        ]);

        // notify other participants
        $participants = ChatParticipant::where('chat_id', $request->chat_id)
            ->where(function ($query) use ($user, $role) {
                $query->where('user_id', '!=', $user->id)
                      ->orWhere('user_type', '!=', $role);
            })
            ->get();

        foreach ($participants as $p) {

            $ably->publishToUser($p->user_id, $p->user_type, [

                'type' => 'new_message',

                'chat_id' => $request->chat_id,
                'message_id' => $message->id,

                'sender_name' => $user->full_name
                    ?? $user->emp_name
                    ?? 'Unknown',

                'preview' => Str::limit(
                    $message->message ?? 'File',
                    50
                )
            ]);
        }

    } catch (\Exception $e) {

        Log::error('Ably publish failed: ' . $e->getMessage());
    }

    /* =========================
        FIREBASE PUSH NOTIFICATIONS
    ========================= */
    try {
        $senderName = $user->full_name ?? $user->emp_name ?? 'Unknown';
        $messagePreview = Str::limit($message->message ?? 'File attachment', 50);

        $credentialsPath = base_path(env('FIREBASE_CREDENTIALS', 'storage/app/firebase/firebase_credentials.json'));

        Log::info('[FCM] Credentials path: ' . $credentialsPath);
        Log::info('[FCM] File exists: ' . (file_exists($credentialsPath) ? 'YES' : 'NO'));
        Log::info('[FCM] Participants count: ' . count($participants));

        if (file_exists($credentialsPath)) {
            $json = json_decode(file_get_contents($credentialsPath), true);
            $projectId = $json['project_id'] ?? null;

            Log::info('[FCM] Project ID: ' . $projectId);

            if ($projectId) {
                $credentials = new ServiceAccountCredentials(
                    'https://www.googleapis.com/auth/firebase.messaging',
                    $credentialsPath
                );

                // fetch the access token
                $tokenData = $credentials->fetchAuthToken();
                $accessToken = $tokenData['access_token'] ?? null;

                Log::info('[FCM] Access token fetched: ' . ($accessToken ? 'YES' : 'NO'));

                if ($accessToken) {
                    foreach ($participants as $p) {
                        $participantUser = $p->user_type === 'admin'
                            ? \App\Models\Admin::find($p->user_id)
                            : \App\Models\Employee::find($p->user_id);

                        Log::info('[FCM] Participant user_id: ' . $p->user_id . ' | user_type: ' . $p->user_type);
                        Log::info('[FCM] FCM Token: ' . ($participantUser->fcm_token ?? 'NULL'));

                        if ($participantUser && $participantUser->fcm_token) {
                            $payload = [
                                'message' => [
                                    'token' => $participantUser->fcm_token,
                                    'notification' => [
                                        'title' => "New Message from {$senderName}",
                                        'body' => $messagePreview,
                                    ],
                                    'data' => [
                                        'chat_id' => (string)$request->chat_id,
                                        'message_id' => (string)$message->id,
                                        'type' => 'new_message'
                                    ]
                                ]
                            ];

                            $response = Http::withToken($accessToken)
                                ->post("https://fcm.googleapis.com/v1/projects/{$projectId}/messages:send", $payload);

                            Log::info('[FCM] Response status: ' . $response->status());
                            Log::info('[FCM] Response body: ' . $response->body());
                        }
                    }
                }
            }
        }
    } catch (\Exception $e) {
        Log::error('[FCM] Firebase push notification failed: ' . $e->getMessage());
    }

    /* =========================
        RESPONSE
    ========================= */

    return response()->json([

        'status' => true,
        'message' => 'Message sent successfully',

        'data' => [

            'id' => $message->id,
            'chat_id' => $message->chat_id,

            'sender_id' => $message->sender_id,
            'sender_type' => $message->sender_type,

            'message' => $message->message,
            'message_type' => $message->message_type,

            'file_url' => $fileUrl,
            'file_name' => $message->file_name,
            'mime_type' => $message->mime_type,
            'file_size' => $message->file_size,

            'reply_to' => $message->reply_to,
            'reply_message' => $replyMessage,

            'is_edited' => $message->is_edited,
            'is_deleted' => $message->is_deleted,

            'created_at' => $message->created_at
        ]
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

       $messages = Message::with('reply')
    ->where('chat_id', $chatId)
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




    // 🔥 EDIT MESSAGE
public function editMessage(Request $request)
{
    $request->validate([
        'message_id' => 'required|exists:messages,id',
        'message' => 'required|string'
    ]);

    // auth user
    $user = $request->user() ?? $request->auth_admin;

    if (!$user) {
        return response()->json([
            'status' => false,
            'message' => 'Unauthenticated'
        ], 401);
    }

    $role = $user->role ?? 'employee';

    // find message
    $message = Message::find($request->message_id);

    if (!$message) {
        return response()->json([
            'status' => false,
            'message' => 'Message not found'
        ], 404);
    }

    // only sender can edit
    if (
        $message->sender_id != $user->id ||
        $message->sender_type != $role
    ) {
        return response()->json([
            'status' => false,
            'message' => 'You can edit only your own messages'
        ], 403);
    }

    // update message
    $message->message = $request->message;
    $message->is_edited = true;
    $message->save();

    // 🔥 ABLY REALTIME EVENT
    try {

        $ably = new AblyService();

        $ably->publishMessageEdit($message->chat_id, [
            'type' => 'message_edited',
            'message_id' => $message->id,
            'chat_id' => $message->chat_id,
            'message' => $message->message,
            'is_edited' => true,
            'updated_at' => $message->updated_at->toISOString()
        ]);

    } catch (\Exception $e) {

        Log::error('Ably edit message failed: ' . $e->getMessage());
    }

    return response()->json([
        'status' => true,
        'message' => 'Message updated successfully',
        'data' => $message
    ]);
}



// 🔥 DELETE MESSAGE
public function deleteMessage(Request $request)
{
    $request->validate([
        'message_id' => 'required|exists:messages,id'
    ]);

    // auth user
    $user = $request->user() ?? $request->auth_admin;

    if (!$user) {
        return response()->json([
            'status' => false,
            'message' => 'Unauthenticated'
        ], 401);
    }

    $role = $user->role ?? 'employee';

    // find message
    $message = Message::find($request->message_id);

    if (!$message) {
        return response()->json([
            'status' => false,
            'message' => 'Message not found'
        ], 404);
    }

    // only sender can delete
    if (
        $message->sender_id != $user->id ||
        $message->sender_type != $role
    ) {
        return response()->json([
            'status' => false,
            'message' => 'You can delete only your own messages'
        ], 403);
    }

    // 🔥 only update delete status
    $message->is_deleted = true;
    $message->save();

    // 🔥 ABLY REALTIME EVENT
    try {

        $ably = new AblyService();

        $ably->publishDeleteMessage($message->chat_id, [

            'type' => 'message_deleted',

            'message_id' => $message->id,
            'chat_id' => $message->chat_id,

            'is_deleted' => true,

            'updated_at' => $message->updated_at->toISOString()
        ]);

    } catch (\Exception $e) {

        Log::error('Ably delete message failed: ' . $e->getMessage());
    }

    return response()->json([
        'status' => true,
        'message' => 'Message deleted successfully'
    ]);
}
}