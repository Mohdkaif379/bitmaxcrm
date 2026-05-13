<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\DeviceToken;
use Illuminate\Http\Request;

class DeviceTokenController extends Controller
{
    /**
     * Store the FCM device token for the authenticated user.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'fcm_token' => 'required|string|max:2048',
            'device_id' => 'nullable|string|max:255',
            'platform' => 'nullable|string|max:50',
        ]);

        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        $userType = $user instanceof Admin ? 'admin' : 'employee';
        $tokenHash = hash('sha256', $validated['fcm_token']);
        $deviceId = $validated['device_id'] ?? null;

        if ($deviceId) {
            DeviceToken::where('user_type', $userType)
                ->where('user_id', $user->id)
                ->where('device_id', $deviceId)
                ->where('token_hash', '!=', $tokenHash)
                ->update(['is_active' => false]);
        }

        DeviceToken::updateOrCreate(
            ['token_hash' => $tokenHash],
            [
                'user_type' => $userType,
                'user_id' => $user->id,
                'fcm_token' => $validated['fcm_token'],
                'device_id' => $deviceId,
                'platform' => $validated['platform'] ?? null,
                'is_active' => true,
                'last_used_at' => now(),
            ]
        );

        // Keep the legacy single-token column updated for older code paths.
        if (strlen($validated['fcm_token']) <= 255) {
            $user->newQuery()
                ->whereKey($user->getKey())
                ->update(['fcm_token' => $validated['fcm_token']]);
        }

        return response()->json([
            'status' => true,
            'message' => 'Device token updated successfully'
        ]);
    }
}
