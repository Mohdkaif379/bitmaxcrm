<?php

namespace App\Http\Controllers\ReportSubmission;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\ReportSubmission;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ReportSubmissionController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'report_status' => ['nullable', 'in:yes,no'],
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'date_filter' => ['nullable', 'in:today,yesterday'],
            'date' => ['nullable', 'date'],
        ]);

        $query = ReportSubmission::query();

        $query->where('report_status', $validated['report_status'] ?? 'yes');

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }

        $now = now('Asia/Kolkata');
        $today = $now->toDateString();

        if (!empty($validated['date_filter'])) {
            $filterDate = $validated['date_filter'] === 'yesterday'
                ? $now->copy()->subDay()->toDateString()
                : $today;
            $query->whereDate('created_at', $filterDate);
        } elseif (!empty($validated['date'])) {
            $query->whereDate('created_at', $validated['date']);
        } else {
            $query->whereDate('created_at', $today);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $matchingEmployeeIds = Employee::query()
                ->where('emp_name', 'like', '%' . $search . '%')
                ->orWhere('emp_email', 'like', '%' . $search . '%')
                ->orWhere('emp_code', 'like', '%' . $search . '%')
                ->pluck('id')
                ->all();

            $query->where(function ($builder) use ($search, $matchingEmployeeIds) {
                $builder->where('report_status', 'like', '%' . $search . '%');

                if (!empty($matchingEmployeeIds)) {
                    $builder->orWhereIn('employee_id', $matchingEmployeeIds);
                }
            });
        }

        $submissions = $query->latest()->paginate(10);
        $employeeIds = collect($submissions->items())->pluck('employee_id')->filter()->unique()->values();
        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');

        return response()->json([
            'status' => true,
            'message' => 'Report submissions fetched successfully.',
            'data' => collect($submissions->items())->map(function (ReportSubmission $submission) use ($employees) {
                $employee = $employees->get((int) $submission->employee_id);

                return [
                    'id' => $submission->id,
                    'employee_id' => $submission->employee_id,
                    'report_status' => $submission->report_status,
                    'submitted_date' => optional($submission->created_at)->toDateString(),
                    'created_at' => $submission->created_at,
                    'updated_at' => $submission->updated_at,
                    'employee' => $employee ? [
                        'id' => $employee->id,
                        'emp_code' => $employee->emp_code,
                        'emp_name' => $employee->emp_name,
                        'emp_email' => $employee->emp_email,
                        'emp_phone' => $employee->emp_phone,
                    ] : null,
                ];
            })->values()->all(),
            'pagination' => [
                'current_page' => $submissions->currentPage(),
                'last_page' => $submissions->lastPage(),
                'per_page' => $submissions->perPage(),
                'total' => $submissions->total(),
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
}
