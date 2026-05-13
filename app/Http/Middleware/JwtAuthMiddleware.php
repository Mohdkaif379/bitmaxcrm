<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\Admin;
use App\Models\Employee;
use Illuminate\Support\Facades\Cache;

class JwtAuthMiddleware
{
    /**
     * Handle an incoming request.
     * Supports both Admin JWT and Employee JWT tokens.
     */
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthenticated. Bearer token is required.'
            ], 401);
        }

        $payload = $this->decodeJwtToken($token);

        if (!$payload) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid or expired token.'
            ], 401);
        }

        $userId = (int) ($payload['sub'] ?? 0);
        $role = $payload['role'] ?? null;

        if ($userId <= 0) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid token payload.'
            ], 401);
        }

        $user = null;

        // 🔥 Check if Admin token
        if ($role === 'admin' || $role === 'sub_admin' || isset($payload['email'])) {
            // Check admin blacklist
            $blacklistKey = 'admin_jwt_blacklist:' . hash('sha256', $token);
            if (Cache::has($blacklistKey)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Token has been revoked.'
                ], 401);
            }

            $user = Admin::find($userId);
            if ($user) {
                $user->role = $role ?? $user->role ?? 'admin';
            }
        }

        // 🔥 Check if Employee token
        if (!$user && ($role === 'employee' || isset($payload['emp_code']))) {
            $blacklistKey = 'employee_jwt_blacklist:' . hash('sha256', $token);
            if (Cache::has($blacklistKey)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Token has been revoked.'
                ], 401);
            }

            $user = Employee::find($userId);
            if ($user) {
                $user->role = 'employee';
            }
        }

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'User not found.'
            ], 401);
        }

        // 🔥 Set user on request so $request->user() works in controllers
        $request->setUserResolver(function () use ($user) {
            return $user;
        });

        // 🔥 Also set auth_admin for controllers that use $request->auth_admin
        $request->merge(['auth_admin' => $user]);
        $request->auth_admin = $user;

        return $next($request);
    }

    /**
     * Decode JWT token (same logic as AdminController & EmployeeLoginController)
     */
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
