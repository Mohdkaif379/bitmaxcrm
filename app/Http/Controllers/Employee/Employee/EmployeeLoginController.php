<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class EmployeeLoginController extends Controller
{
    public function login(Request $request)
    {
        $validated = $request->validate([
            'emp_code' => ['required', 'string'],
            'password' => ['required', 'string'],
        ]);

        $employee = Employee::where('emp_code', $validated['emp_code'])->first();

        if (!$employee || !Hash::check($validated['password'], $employee->password)) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid employee code or password.',
            ], 401);
        }

        $token = $this->createJwtToken($employee);
        $this->logEmployeeAuthAction($request, $employee, 'login', 'logged in');

        return response()->json([
            'status' => true,
            'message' => 'Login successful.',
            'token_type' => 'Bearer',
            'access_token' => $token,
            'expires_in' => null,
            'data' => $this->transformEmployee($employee),
        ]);
    }

    public function logout(Request $request)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Bearer token is required.',
            ], 400);
        }

        $payload = $this->decodeJwtToken($token);

        if (!$payload) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid or expired token.',
            ], 401);
        }

        $blacklistKey = 'employee_jwt_blacklist:' . hash('sha256', $token);
        Cache::forever($blacklistKey, true);
        $employee = $this->resolveEmployeeFromPayload($payload);
        if ($employee) {
            $this->logEmployeeAuthAction($request, $employee, 'logout', 'logged out');
        }

        return response()->json([
            'status' => true,
            'message' => 'Logout successful.',
        ]);
    }

    private function transformEmployee(Employee $employee): array
    {
        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null;

        return $data;
    }

    private function createJwtToken(Employee $employee): string
    {
        $now = time();

        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT',
        ];

        $payload = [
            'iss' => config('app.url'),
            'sub' => (string) $employee->id,
            'emp_code' => $employee->emp_code,
            'role' => 'employee',
            'iat' => $now,
            'nbf' => $now,
            'jti' => (string) Str::uuid(),
        ];

        $encodedHeader = $this->base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->jwtSecret(), true);
        $encodedSignature = $this->base64UrlEncode($signature);

        return $encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature;
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

        $blacklistKey = 'employee_jwt_blacklist:' . hash('sha256', $token);
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

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }

    private function resolveEmployeeFromPayload(array $payload): ?Employee
    {
        if (($payload['role'] ?? null) !== 'employee') {
            return null;
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        if ($employeeId <= 0) {
            return null;
        }

        return Employee::find($employeeId);
    }

    private function logEmployeeAuthAction(Request $request, Employee $employee, string $action, string $actionText): void
    {
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = null;
        $log->employee_id = $employee->id;
        $log->model = class_basename(Employee::class);
        $log->action = $action;
        $log->description = sprintf(
            'employee(%s) %s',
            $employeeName,
            $actionText
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
