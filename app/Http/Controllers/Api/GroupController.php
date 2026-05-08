<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Chat;
use App\Models\ChatParticipant;

class GroupController extends Controller
{
    // 🔥 CREATE GROUP
    public function create(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'participants' => 'array'
        ]);

        $chat = Chat::create([
            'type' => 'group',
            'name' => $request->name,
            'created_by_id' => $request->user()->id,
            'created_by_type' => $request->user()->role ?? 'employee'
        ]);

        // admin add
        ChatParticipant::create([
            'chat_id' => $chat->id,
            'user_id' => $request->user()->id,
            'user_type' => $request->user()->role ?? 'employee',
            'role' => 'admin',
            'joined_at' => now()
        ]);

        // members add
        foreach ($request->participants ?? [] as $p) {
            ChatParticipant::create([
                'chat_id' => $chat->id,
                'user_id' => $p['id'],
                'user_type' => $p['type'],
                'role' => 'member',
                'joined_at' => now()
            ]);
        }

        return response()->json([
            'message' => 'Group created',
            'data' => $chat->load('participants')
        ]);
    }

    // 🔥 GROUP DETAILS
    public function details($id)
    {
        return Chat::with('participants.user')->findOrFail($id);
    }

    // 🔥 RENAME GROUP
    public function rename(Request $request, $id)
    {
        $request->validate([
            'name' => 'required'
        ]);

        Chat::findOrFail($id)->update([
            'name' => $request->name
        ]);

        return response()->json(['message' => 'Group renamed']);
    }

    // 🔥 ADD MEMBERS
    public function addMembers(Request $request, $id)
    {
        foreach ($request->participants as $p) {
            ChatParticipant::firstOrCreate([
                'chat_id' => $id,
                'user_id' => $p['id'],
                'user_type' => $p['type']
            ], [
                'role' => 'member',
                'joined_at' => now()
            ]);
        }

        return response()->json(['message' => 'Members added']);
    }

    // 🔥 REMOVE MEMBER
    public function removeMember(Request $request, $id)
    {
        ChatParticipant::where('chat_id', $id)
            ->where('user_id', $request->user_id)
            ->delete();

        return response()->json(['message' => 'Member removed']);
    }

    // 🔥 LEAVE GROUP
    public function leave(Request $request, $id)
    {
        ChatParticipant::where('chat_id', $id)
            ->where('user_id', $request->user()->id)
            ->delete();

        return response()->json(['message' => 'Left group']);
    }
}