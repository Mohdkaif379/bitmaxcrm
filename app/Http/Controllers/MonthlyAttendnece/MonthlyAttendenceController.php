<?php

namespace App\Http\Controllers\MonthlyAttendnece;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Attendence;
use App\Models\Employee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class MonthlyAttendenceController extends Controller
{
    public function employeeMonthlyAttendance(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'month' => ['required', 'string', 'max:20'],
            'year' => ['required', 'integer', 'min:2000', 'max:2100'],
        ]);

        $monthNumber = $this->monthNumberFromName($validated['month']);
        if ($monthNumber === null) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid month. Use month names like january, february, march.',
            ], 422);
        }

        $employeeId = (int) $validated['employee_id'];
        $year = (int) $validated['year'];

        $attendances = Attendence::with('employee')
            ->where('employee_id', $employeeId)
            ->whereMonth('date', $monthNumber)
            ->whereYear('date', $year)
            ->orderBy('date')
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Employee monthly attendances fetched successfully.',
            'data' => $attendances->map(fn (Attendence $attendance) => $this->transformAttendance($attendance))->values(),
            'meta' => [
                'employee_id' => $employeeId,
                'month' => strtolower(trim($validated['month'])),
                'year' => $year,
                'total_records' => $attendances->count(),
            ],
        ]);
    }

    private function monthNumberFromName(string $month): ?int
    {
        $map = [
            'january' => 1,
            'february' => 2,
            'march' => 3,
            'april' => 4,
            'may' => 5,
            'june' => 6,
            'july' => 7,
            'august' => 8,
            'september' => 9,
            'october' => 10,
            'november' => 11,
            'december' => 12,
        ];

        return $map[strtolower(trim($month))] ?? null;
    }

    private function transformAttendance(Attendence $attendance): array
    {
        $data = $attendance->toArray();
        $data['profile_image'] = $attendance->profile_image ? url(Storage::url($attendance->profile_image)) : null;
        $data['employee'] = $attendance->employee ? $this->transformEmployee($attendance->employee) : null;

        return $data;
    }

    private function transformEmployee(Employee $employee): array
    {
        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null;

        return $data;
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
}
