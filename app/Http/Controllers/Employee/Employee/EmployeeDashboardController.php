<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Attendence;
use App\Models\Employee;
use App\Models\LeaveManagement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class EmployeeDashboardController extends Controller
{
    public function dashboard(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $attendanceQuery = Attendence::query()->where('employee_id', $employee->id);
        $attendanceSummary = [
            'total_days' => (clone $attendanceQuery)->count(),
            'present_days' => (clone $attendanceQuery)->where('status', 'present')->count(),
            'half_days' => (clone $attendanceQuery)->where('status', 'halfday')->count(),
            'absent_days' => (clone $attendanceQuery)->where('status', 'absent')->count(),
            'holiday_days' => (clone $attendanceQuery)->where('status', 'holiday')->count(),
        ];

        $leaveQuery = LeaveManagement::query()->where('employee_id', $employee->id);
        $leaveSummary = [
            'total_leave_requests' => (clone $leaveQuery)->count(),
            'approved_leave_requests' => (clone $leaveQuery)->where('status', 'approved')->count(),
            'pending_leave_requests' => (clone $leaveQuery)->where('status', 'pending')->count(),
            'rejected_leave_requests' => (clone $leaveQuery)->where('status', 'rejected')->count(),
            'total_leave_days' => (int) ((clone $leaveQuery)->sum('total_days') ?? 0),
        ];

        return response()->json([
            'status' => true,
            'message' => 'Employee dashboard fetched successfully.',
            'data' => [
                'employee' => $this->transformEmployee($employee),
                'attendance_summary' => $attendanceSummary,
                'leave_summary' => $leaveSummary,
            ],
        ]);
    }

    private function transformEmployee(Employee $employee): array
    {
        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null;

        return $data;
    }

    private function authenticatedEmployeeFromToken(Request $request): ?Employee
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        if (($payload['role'] ?? null) !== 'employee') {
            return null;
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        if ($employeeId <= 0) {
            return null;
        }

        return Employee::find($employeeId);
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

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }
}
