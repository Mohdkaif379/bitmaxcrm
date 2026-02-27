<?php

namespace App\Http\Controllers\Notification;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Notification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class NotificationController extends Controller
{
    public function index(Request $request)
    {
        $auth = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$auth) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'unread_only' => ['nullable', 'boolean'],
        ]);

        $admin = $auth['admin'];
        $role = $auth['role'];
        $query = Notification::query();

        if ($role !== 'admin') {
            $query->where('admin_id', $admin->id);
        }

        if (($validated['unread_only'] ?? false) === true) {
            $query->where('is_read', false);
        }

        $notifications = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Notifications fetched successfully.',
            'data' => $notifications->items(),
            'pagination' => [
                'current_page' => $notifications->currentPage(),
                'last_page' => $notifications->lastPage(),
                'per_page' => $notifications->perPage(),
                'total' => $notifications->total(),
            ],
        ]);
    }

    public function markAllRead(Request $request)
    {
        $auth = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$auth) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $admin = $auth['admin'];
        $role = $auth['role'];
        $query = Notification::query()->where('is_read', false);

        if ($role !== 'admin') {
            $query->where('admin_id', $admin->id);
        }

        $updatedCount = $query->update(['is_read' => true]);

        return response()->json([
            'status' => true,
            'message' => 'All notifications marked as read successfully.',
            'data' => [
                'updated_count' => $updatedCount,
            ],
        ]);
    }

    public function markSingleRead(Request $request, int $id)
    {
        $auth = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$auth) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $admin = $auth['admin'];
        $role = $auth['role'];
        $query = Notification::query()->where('id', $id);

        if ($role !== 'admin') {
            $query->where('admin_id', $admin->id);
        }

        $notification = $query->first();
        if (!$notification) {
            return response()->json([
                'status' => false,
                'message' => 'Notification not found.',
            ], 404);
        }

        $notification->is_read = true;
        $notification->save();

        return response()->json([
            'status' => true,
            'message' => 'Notification marked as read successfully.',
            'data' => $notification,
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $auth = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$auth) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $admin = $auth['admin'];
        $role = $auth['role'];
        $query = Notification::query()->where('id', $id);

        if ($role !== 'admin') {
            $query->where('admin_id', $admin->id);
        }

        $notification = $query->first();
        if (!$notification) {
            return response()->json([
                'status' => false,
                'message' => 'Notification not found.',
            ], 404);
        }

        $notification->delete();

        return response()->json([
            'status' => true,
            'message' => 'Notification deleted successfully.',
        ]);
    }

    private function authenticatedAdminOrSubAdminFromToken(Request $request): ?array
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        $role = strtolower((string) ($payload['role'] ?? ''));
        if (!in_array($role, ['admin', 'sub_admin', 'subadmin'], true)) {
            return null;
        }

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return null;
        }

        $admin = Admin::find($adminId);
        if (!$admin) {
            return null;
        }

        return [
            'admin' => $admin,
            'role' => $role,
        ];
    }

    private function decodeJwtToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $signature = $this->base64UrlDecode($encodedSignature);
        if ($signature === false) {
            return null;
        }

        $expectedSignature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->jwtSecret(), true);
        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }

        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === false) {
            return null;
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return null;
        }

        $blacklistKey = 'admin_jwt_blacklist:' . hash('sha256', $token);
        if (Cache::has($blacklistKey)) {
            return null;
        }

        return $payload;
    }

    private function jwtSecret(): string
    {
        $secret = env('JWT_SECRET');
        if (!empty($secret)) {
            return $secret;
        }

        $appKey = (string) config('app.key', '');
        if (str_starts_with($appKey, 'base64:')) {
            $decoded = base64_decode(substr($appKey, 7), true);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $appKey;
    }

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }
}
