<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Attendence;
use App\Models\Employee;
use App\Models\ReportSubmission;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class EmployeeAttendenceController extends Controller
{
    public function myAttendance(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'month' => ['required', 'string', 'max:20'],
            'year' => ['nullable', 'integer', 'min:2000', 'max:2100'],
        ]);

        $query = Attendence::with('employee')->where('employee_id', $employee->id);
        $monthNumber = $this->monthNumberFromName($validated['month']);
        if ($monthNumber === null) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid month. Use month names like january, february, march.',
            ], 422);
        }

        $year = (int) ($validated['year'] ?? now('Asia/Kolkata')->year);
        $query->whereMonth('date', $monthNumber)
            ->whereYear('date', $year);

        $attendances = $query->latest()->paginate(10);
        $attendances->getCollection()->transform(
            fn (Attendence $attendance) => $this->transformAttendance($attendance)
        );

        return response()->json([
            'status' => true,
            'message' => 'My attendances fetched successfully.',
            'data' => $attendances->items(),
            'pagination' => [
                'current_page' => $attendances->currentPage(),
                'last_page' => $attendances->lastPage(),
                'per_page' => $attendances->perPage(),
                'total' => $attendances->total(),
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

    public function markIn(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $request->validate([
            'profile_image' => ['required', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
            'report_status' => ['nullable', 'in:yes,no'],
        ]);

        $now = now('Asia/Kolkata');
        $today = $now->toDateString();

        $attendance = Attendence::firstOrNew([
            'employee_id' => $employee->id,
            'date' => $today,
        ]);

        if ($attendance->mark_in) {
            return response()->json([
                'status' => false,
                'message' => 'Mark in already done for today.',
            ], 422);
        }

        $attendance->mark_in = $now->format('H:i:s');
        $attendance->status = $attendance->mark_in <= '09:31:00' ? 'present' : 'halfday';
        $attendance->ip_address = $request->ip();
        $attendance->profile_image = $request->file('profile_image')->store('attendence/mark_in', 'public');
        $attendance->save();
        $attendance->load('employee');

        return response()->json([
            'status' => true,
            'message' => 'Mark in successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function markOut(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $request->validate([
            'profile_image' => ['required', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', $employee->id)
            ->whereDate('date', $today)
            ->first();

        if (!$attendance || !$attendance->mark_in) {
            return response()->json([
                'status' => false,
                'message' => 'Please mark in first.',
            ], 422);
        }

        if ($attendance->mark_out) {
            return response()->json([
                'status' => false,
                'message' => 'Mark out already done for today.',
            ], 422);
        }

        $attendance->mark_out = now('Asia/Kolkata')->format('H:i:s');
        $attendance->status = ($attendance->mark_in <= '09:31:00' && $attendance->mark_out >= '18:30:00')
            ? 'present'
            : 'halfday';
        $attendance->ip_address = $request->ip();
        $attendance->profile_image = $request->file('profile_image')->store('attendence/mark_out', 'public');
        $attendance->save();

        $reportSubmission = ReportSubmission::create([
            'employee_id' => $employee->id,
            'report_status' => $request->input('report_status', 'no'),
        ]);

        $attendance->load('employee');

        return response()->json([
            'status' => true,
            'message' => 'Mark out successful.',
            'data' => array_merge(
                $this->transformAttendance($attendance),
                [
                'report_submission' => $reportSubmission->toArray(),
                ]
            ),
        ]);
    }

    public function breakStart(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $request->validate([
            'profile_image' => ['required', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', $employee->id)
            ->whereDate('date', $today)
            ->first();

        if (!$attendance || !$attendance->mark_in) {
            return response()->json([
                'status' => false,
                'message' => 'Please mark in first.',
            ], 422);
        }

        if ($attendance->mark_out) {
            return response()->json([
                'status' => false,
                'message' => 'Break cannot start after mark out.',
            ], 422);
        }

        if ($attendance->break_start) {
            return response()->json([
                'status' => false,
                'message' => 'Break start already marked.',
            ], 422);
        }

        $attendance->break_start = now('Asia/Kolkata')->format('H:i:s');
        $attendance->ip_address = $request->ip();
        $attendance->profile_image = $request->file('profile_image')->store('attendence/break_start', 'public');
        $attendance->save();
        $attendance->load('employee');

        return response()->json([
            'status' => true,
            'message' => 'Break start successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function breakEnd(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $request->validate([
            'profile_image' => ['required', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', $employee->id)
            ->whereDate('date', $today)
            ->first();

        if (!$attendance || !$attendance->mark_in) {
            return response()->json([
                'status' => false,
                'message' => 'Please mark in first.',
            ], 422);
        }

        if (!$attendance->break_start) {
            return response()->json([
                'status' => false,
                'message' => 'Please mark break start first.',
            ], 422);
        }

        if ($attendance->break_end) {
            return response()->json([
                'status' => false,
                'message' => 'Break end already marked.',
            ], 422);
        }

        $attendance->break_end = now('Asia/Kolkata')->format('H:i:s');
        $attendance->ip_address = $request->ip();
        $attendance->profile_image = $request->file('profile_image')->store('attendence/break_end', 'public');
        $attendance->save();
        $attendance->load('employee');

        return response()->json([
            'status' => true,
            'message' => 'Break end successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
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
