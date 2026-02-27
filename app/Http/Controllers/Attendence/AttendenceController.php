<?php

namespace App\Http\Controllers\Attendence;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Attendence;
use App\Models\Employee;
use App\Models\Log;
use App\Models\OfficeIpSetting;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class AttendenceController extends Controller
{
    public function index(Request $request)
    {
        $validated = $request->validate([
            'filter' => ['nullable', 'in:daily,weekly,monthly,yearly'],
        ]);

        $query = Attendence::with('employee');
        $filter = $validated['filter'] ?? null;

        if ($filter === 'daily') {
            $query->whereDate('date', now('Asia/Kolkata')->toDateString());
        } elseif ($filter === 'weekly') {
            $start = Carbon::now('Asia/Kolkata')->startOfWeek()->toDateString();
            $end = Carbon::now('Asia/Kolkata')->endOfWeek()->toDateString();
            $query->whereBetween('date', [$start, $end]);
        } elseif ($filter === 'monthly') {
            $query->whereMonth('date', now('Asia/Kolkata')->month)
                ->whereYear('date', now('Asia/Kolkata')->year);
        } elseif ($filter === 'yearly') {
            $query->whereYear('date', now('Asia/Kolkata')->year);
        }

        $attendances = $query->latest()->paginate(10);
        $attendances->getCollection()->transform(
            fn (Attendence $attendance) => $this->transformAttendance($attendance)
        );

        return response()->json([
            'status' => true,
            'message' => 'Attendances fetched successfully.',
            'data' => $attendances->items(),
            'pagination' => [
                'current_page' => $attendances->currentPage(),
                'last_page' => $attendances->lastPage(),
                'per_page' => $attendances->perPage(),
                'total' => $attendances->total(),
            ],
        ]);
    }

    public function showByEmployee(int $employeeId)
    {
        $employee = Employee::find($employeeId);

        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Employee not found.',
            ], 404);
        }

        $attendances = Attendence::with('employee')
            ->where('employee_id', $employeeId)
            ->latest()
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Employee attendances fetched successfully.',
            'data' => $attendances->map(fn (Attendence $attendance) => $this->transformAttendance($attendance))->values(),
        ]);
    }

    public function markIn(Request $request)
    {
        if ($ipRestrictionResponse = $this->ensureRequestFromSyncedOfficeIp($request)) {
            return $ipRestrictionResponse;
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'profile_image' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $now = now('Asia/Kolkata');
        $today = $now->toDateString();

        $attendance = Attendence::firstOrNew([
            'employee_id' => (int) $validated['employee_id'],
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

        if ($request->hasFile('profile_image')) {
            $attendance->profile_image = $request->file('profile_image')->store('attendence/mark_in', 'public');
        }

        $attendance->save();

        $this->logAttendanceAction($request, $attendance, 'mark_in', 'marked attendance in');

        return response()->json([
            'status' => true,
            'message' => 'Mark in successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function markOut(Request $request)
    {
        if ($ipRestrictionResponse = $this->ensureRequestFromSyncedOfficeIp($request)) {
            return $ipRestrictionResponse;
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'profile_image' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', (int) $validated['employee_id'])
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

        $markInOnTime = $attendance->mark_in <= '09:31:00';
        $markOutOnTime = $attendance->mark_out >= '18:30:00';
        $attendance->status = ($markInOnTime && $markOutOnTime) ? 'present' : 'halfday';
        $attendance->ip_address = $request->ip();

        if ($request->hasFile('profile_image')) {
            $attendance->profile_image = $request->file('profile_image')->store('attendence/mark_out', 'public');
        }

        $attendance->save();

        $this->logAttendanceAction($request, $attendance, 'mark_out', 'marked attendance out');

        return response()->json([
            'status' => true,
            'message' => 'Mark out successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function breakStart(Request $request)
    {
        if ($ipRestrictionResponse = $this->ensureRequestFromSyncedOfficeIp($request)) {
            return $ipRestrictionResponse;
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'profile_image' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', (int) $validated['employee_id'])
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

        if ($request->hasFile('profile_image')) {
            $attendance->profile_image = $request->file('profile_image')->store('attendence/break_start', 'public');
        }

        $attendance->save();

        $this->logAttendanceAction($request, $attendance, 'break_start', 'started break');

        return response()->json([
            'status' => true,
            'message' => 'Break start successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function breakEnd(Request $request)
    {
        if ($ipRestrictionResponse = $this->ensureRequestFromSyncedOfficeIp($request)) {
            return $ipRestrictionResponse;
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'profile_image' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
        ]);

        $today = now('Asia/Kolkata')->toDateString();
        $attendance = Attendence::where('employee_id', (int) $validated['employee_id'])
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

        if ($request->hasFile('profile_image')) {
            $attendance->profile_image = $request->file('profile_image')->store('attendence/break_end', 'public');
        }

        $attendance->save();

        $this->logAttendanceAction($request, $attendance, 'break_end', 'ended break');

        return response()->json([
            'status' => true,
            'message' => 'Break end successful.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function update(Request $request, int $id)
    {
        if (!$this->isAdminToken($request)) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'date' => ['sometimes', 'date'],
            'mark_in' => ['nullable', 'date_format:H:i:s'],
            'mark_out' => ['nullable', 'date_format:H:i:s'],
            'break_start' => ['nullable', 'date_format:H:i:s'],
            'break_end' => ['nullable', 'date_format:H:i:s'],
            'profile_image' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:5120'],
            'status' => ['nullable', 'in:present,absent,halfday,holiday'],
        ]);

        $attendance = Attendence::where('id', $id)
            ->where('employee_id', (int) $validated['employee_id'])
            ->first();

        if (!$attendance) {
            return response()->json([
                'status' => false,
                'message' => 'Attendance not found for this employee.',
            ], 404);
        }

        if (array_key_exists('date', $validated)) {
            $attendance->date = $validated['date'];
        }

        if (array_key_exists('mark_in', $validated)) {
            $attendance->mark_in = $validated['mark_in'];
        }

        if (array_key_exists('mark_out', $validated)) {
            $attendance->mark_out = $validated['mark_out'];
        }

        if (array_key_exists('break_start', $validated)) {
            $attendance->break_start = $validated['break_start'];
        }

        if (array_key_exists('break_end', $validated)) {
            $attendance->break_end = $validated['break_end'];
        }

        if ($request->hasFile('profile_image')) {
            $attendance->profile_image = $request->file('profile_image')->store('attendence/edit', 'public');
        }

        if (array_key_exists('status', $validated)) {
            $attendance->status = $validated['status'];
        } else {
            $attendance->status = $this->resolveAttendanceStatus($attendance->mark_in, $attendance->mark_out, $attendance->status);
        }
        $attendance->ip_address = $request->ip();

        $attendance->save();
        $attendance->load('employee');

        $this->logAttendanceAction($request, $attendance, 'update', 'updated attendance');

        return response()->json([
            'status' => true,
            'message' => 'Attendance updated successfully.',
            'data' => $this->transformAttendance($attendance),
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $attendance = Attendence::find($id);

        if (!$attendance) {
            return response()->json([
                'status' => false,
                'message' => 'Attendance not found.',
            ], 404);
        }

        if ($attendance->profile_image) {
            $relativePath = str_replace('/storage/', '', parse_url($attendance->profile_image, PHP_URL_PATH) ?? '');
            $pathToDelete = $relativePath ?: $attendance->profile_image;

            if (Storage::disk('public')->exists($pathToDelete)) {
                Storage::disk('public')->delete($pathToDelete);
            }
        }

        $employeeId = $attendance->employee_id;
        $attendance->delete();

        $this->logAttendanceDeleteAction($request, $employeeId);

        return response()->json([
            'status' => true,
            'message' => 'Attendance deleted successfully.',
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

    private function resolveAttendanceStatus(?string $markIn, ?string $markOut, ?string $currentStatus = null): string
    {
        if (!$markIn) {
            return $currentStatus ?: 'present';
        }

        if (!$markOut) {
            return $markIn <= '09:31:00' ? 'present' : 'halfday';
        }

        return ($markIn <= '09:31:00' && $markOut >= '18:30:00') ? 'present' : 'halfday';
    }

    private function isAdminToken(Request $request): bool
    {
        $token = $request->bearerToken();
        if (!$token) {
            return false;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return false;
        }

        if (($payload['role'] ?? null) !== 'admin') {
            return false;
        }

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return false;
        }

        return Admin::where('id', $adminId)->exists();
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

    private function logAttendanceAction(Request $request, Attendence $attendance, string $action, string $actionText): void
    {
        $adminId = $this->resolveAdminIdFromToken($request);
        $adminName = $this->resolveAdminName($adminId);
        $employeeName = $this->resolveEmployeeName($attendance->employee_id);

        $log = new Log();
        $log->admin_id = $adminId;
        $log->employee_id = $attendance->employee_id;
        $log->model = class_basename($attendance);
        $log->action = $action;
        $log->description = sprintf(
            '(%s) %s this employee(%s)',
            $adminName,
            $actionText,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logAttendanceDeleteAction(Request $request, ?int $employeeId): void
    {
        $adminId = $this->resolveAdminIdFromToken($request);
        $adminName = $this->resolveAdminName($adminId);
        $employeeName = $this->resolveEmployeeName($employeeId);

        $log = new Log();
        $log->admin_id = $adminId;
        $log->employee_id = $employeeId;
        $log->model = class_basename(Attendence::class);
        $log->action = 'delete';
        $log->description = sprintf(
            '(%s) deleted attendance for employee(%s)',
            $adminName,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function resolveAdminIdFromToken(Request $request): ?int
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload || ($payload['role'] ?? null) !== 'admin') {
            return null;
        }

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return null;
        }

        return Admin::where('id', $adminId)->exists() ? $adminId : null;
    }

    private function resolveAdminName(?int $adminId): string
    {
        if (!$adminId) {
            return 'unknown admin';
        }

        $admin = Admin::find($adminId);
        return $admin?->full_name ?: 'unknown admin';
    }

    private function resolveEmployeeName(?int $employeeId): string
    {
        if (!$employeeId) {
            return 'unknown employee';
        }

        $employee = Employee::find($employeeId);
        return $employee?->emp_name ?: 'unknown employee';
    }

    private function ensureRequestFromSyncedOfficeIp(Request $request): ?JsonResponse
    {
        $syncedIp = OfficeIpSetting::query()
            ->where('is_active', true)
            ->latest('id')
            ->value('ip_address');

        if (empty($syncedIp)) {
            return response()->json([
                'status' => false,
                'message' => 'Office IP is not synced yet. Please sync office IP first.',
            ], 422);
        }

        if ($request->ip() !== $syncedIp) {
            return response()->json([
                'status' => false,
                'message' => 'Attendance can be marked only from synced office IP.',
                'data' => [
                    'request_ip' => $request->ip(),
                    'synced_office_ip' => $syncedIp,
                ],
            ], 422);
        }

        return null;
    }
}
