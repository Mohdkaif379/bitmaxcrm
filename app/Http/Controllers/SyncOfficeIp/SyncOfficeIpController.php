<?php

namespace App\Http\Controllers\SyncOfficeIp;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Log;
use App\Models\OfficeIpSetting;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class SyncOfficeIpController extends Controller
{
    public function sync(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $ipAddress = (string) $request->ip();

        OfficeIpSetting::query()->where('is_active', true)->update(['is_active' => false]);

        $setting = OfficeIpSetting::create([
            'ip_address' => $ipAddress,
            'synced_by_admin_id' => $admin->id,
            'is_active' => true,
        ]);

        $this->logSyncOfficeIpAction($request, $admin, $ipAddress);

        return response()->json([
            'status' => true,
            'message' => 'Office IP synced successfully.',
            'data' => [
                'id' => $setting->id,
                'ip_address' => $setting->ip_address,
                'synced_by_admin_id' => $setting->synced_by_admin_id,
                'is_active' => $setting->is_active,
                'created_at' => $setting->created_at,
            ],
        ]);
    }

    public function current(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $setting = OfficeIpSetting::query()->where('is_active', true)->latest('id')->first();

        return response()->json([
            'status' => true,
            'message' => 'Office IP fetched successfully.',
            'data' => [
                'ip_address' => $setting?->ip_address,
                'synced_by_admin_id' => $setting?->synced_by_admin_id,
                'is_active' => (bool) ($setting?->is_active ?? false),
                'request_ip' => $request->ip(),
                'matches_synced_ip' => $setting ? $request->ip() === $setting->ip_address : false,
            ],
        ]);
    }

    private function authenticatedAdminOrSubAdminFromToken(Request $request): ?Admin
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

        return Admin::find($adminId);
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

    private function logSyncOfficeIpAction(Request $request, Admin $admin, string $ipAddress): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(OfficeIpSetting::class);
        $log->action = 'sync_ip';
        $log->description = sprintf(
            'admin(%s) synced office IP (%s)',
            $adminName,
            $ipAddress
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
