<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\LeaveManagement;
use App\Models\Log;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class EmployeeLeaveManageController extends Controller
{
    public function store(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'start_date' => ['required', 'date'],
            'end_date' => ['required', 'date', 'after_or_equal:start_date'],
            'subject' => ['required', 'string', 'max:255'],
            'description' => ['required', 'string'],
            'leave_type' => ['required', 'string', 'max:255'],
            'file' => ['nullable', 'file', 'mimes:jpg,jpeg,png,pdf,doc,docx,webp', 'max:5120'],
        ]);

        $totalDays = Carbon::parse($validated['start_date'])->diffInDays(Carbon::parse($validated['end_date'])) + 1;

        $leave = new LeaveManagement();
        $leave->employee_id = $employee->id;
        $leave->start_date = $validated['start_date'];
        $leave->end_date = $validated['end_date'];
        $leave->subject = $validated['subject'];
        $leave->description = $validated['description'];
        $leave->leave_type = $validated['leave_type'];
        $leave->total_days = $totalDays;
        $leave->status = 'pending';
        $leave->approved_by = null;

        if ($request->hasFile('file')) {
            $leave->file = $request->file('file')->store('leave-management/files', 'public');
        }

        $leave->save();
        $leave->load('employee');
        $this->logEmployeeLeaveAction($request, $employee, 'create', 'submitted leave request');

        return response()->json([
            'status' => true,
            'message' => 'Leave request submitted successfully.',
            'data' => $this->transformLeave($leave),
        ], 201);
    }

    public function myLeaves(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $leaves = LeaveManagement::with('employee')
            ->where('employee_id', $employee->id)
            ->latest('id')
            ->get();
        $this->logEmployeeLeaveAction($request, $employee, 'view', 'viewed leave requests');

        return response()->json([
            'status' => true,
            'message' => 'My leave requests fetched successfully.',
            'data' => $leaves->map(fn (LeaveManagement $leave) => $this->transformLeave($leave))->values(),
        ]);
    }

    private function transformLeave(LeaveManagement $leave): array
    {
        $data = $leave->toArray();
        $data['file'] = $leave->file ? url(Storage::url($leave->file)) : null;

        if ($leave->relationLoaded('employee') && $leave->employee) {
            $employeeData = $leave->employee->toArray();
            unset($employeeData['password']);
            $employeeData['profile_photo'] = $leave->employee->profile_photo
                ? url(Storage::url($leave->employee->profile_photo))
                : null;
            $data['employee'] = $employeeData;
        } else {
            $data['employee'] = null;
        }

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

    private function logEmployeeLeaveAction(Request $request, Employee $employee, string $action, string $actionText): void
    {
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = null;
        $log->employee_id = $employee->id;
        $log->model = class_basename(LeaveManagement::class);
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
