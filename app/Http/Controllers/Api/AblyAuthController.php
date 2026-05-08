<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\AblyService;
use Illuminate\Http\Request;

class AblyAuthController extends Controller
{
    /**
     * 🔥 Generate Ably token for frontend real-time connection
     * Frontend calls this to get auth token for Ably SDK
     */
    public function token(Request $request)
    {
        $user = $request->user() ?? $request->auth_admin;

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        $role = $user->role ?? 'employee';
        $clientId = "{$role}:{$user->id}";

        try {
            $ably = new AblyService();
            $tokenRequest = $ably->createTokenRequest($clientId);

            return response()->json([
                'status' => true,
                'token_request' => $tokenRequest,
                'client_id' => $clientId
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => 'Failed to generate Ably token',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}
