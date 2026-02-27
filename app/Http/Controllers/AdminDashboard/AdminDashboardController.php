<?php

namespace App\Http\Controllers\AdminDashboard;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\EmployeePayroll;
use App\Models\Expenses;
use App\Models\LeaveManagement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class AdminDashboardController extends Controller
{
    public function recentEmployees(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $employees = Employee::query()
            ->latest('id')
            ->limit(5)
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Recent employees fetched successfully.',
            'data' => $employees->map(function (Employee $employee) {
                return [
                    'id' => $employee->id,
                    'emp_code' => $employee->emp_code,
                    'emp_name' => $employee->emp_name,
                    'emp_email' => $employee->emp_email,
                    'emp_phone' => $employee->emp_phone,
                    'joining_date' => $employee->joining_date,
                    'position' => $employee->position,
                    'department' => $employee->department,
                    'status' => $employee->status,
                    'role' => $employee->role,
                    'profile_photo' => $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null,
                    'created_at' => $employee->created_at,
                    'updated_at' => $employee->updated_at,
                ];
            })->values()->all(),
        ]);
    }

    public function dashboardStats(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $now = now('Asia/Kolkata');
        $totalEmployees = Employee::count();

        $salaryBasic = (float) EmployeePayroll::sum('basic_salary');
        $salaryHra = (float) EmployeePayroll::sum('hra');
        $salaryConveyance = (float) EmployeePayroll::sum('conveyance_allowance');
        $salaryMedical = (float) EmployeePayroll::sum('medical_allowance');
        $monthlySalaryExpense = $salaryBasic + $salaryHra + $salaryConveyance + $salaryMedical;

        $currentMonthExpense = (float) Expenses::query()
            ->whereYear('date', $now->year)
            ->whereMonth('date', $now->month)
            ->sum('amount');

        return response()->json([
            'status' => true,
            'message' => 'Admin dashboard stats fetched successfully.',
            'data' => [
                'total_employees' => $totalEmployees,
                'monthly_salary_expense' => round($monthlySalaryExpense, 2),
                'current_month_expense' => round($currentMonthExpense, 2),
                'month' => strtolower($now->format('F')),
                'year' => (int) $now->year,
            ],
        ]);
    }

    public function recentLeaves(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $leaves = LeaveManagement::query()
            ->with('employee')
            ->latest('id')
            ->limit(3)
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Recent leaves fetched successfully.',
            'data' => $leaves->map(function (LeaveManagement $leave) {
                $employee = $leave->employee;
                $employeeData = null;

                if ($employee) {
                    $employeeData = $employee->toArray();
                    unset($employeeData['password']);
                    $employeeData['profile_photo'] = $employee->profile_photo
                        ? url(Storage::url($employee->profile_photo))
                        : null;
                }

                return [
                    'id' => $leave->id,
                    'employee_id' => $leave->employee_id,
                    'start_date' => $leave->start_date,
                    'end_date' => $leave->end_date,
                    'subject' => $leave->subject,
                    'description' => $leave->description,
                    'leave_type' => $leave->leave_type,
                    'total_days' => $leave->total_days,
                    'status' => $leave->status,
                    'file' => $leave->file ? url(Storage::url($leave->file)) : null,
                    'approved_by' => $leave->approved_by,
                    'created_at' => $leave->created_at,
                    'updated_at' => $leave->updated_at,
                    'employee' => $employeeData,
                ];
            })->values()->all(),
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
}
