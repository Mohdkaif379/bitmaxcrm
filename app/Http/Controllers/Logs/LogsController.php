<?php

namespace App\Http\Controllers\Logs;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class LogsController extends Controller
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
            'model' => ['nullable', 'string', 'max:255'],
            'action' => ['nullable', 'string', 'max:255'],
            'admin_id' => ['nullable', 'integer', 'exists:admins,id'],
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'date' => ['nullable', 'date'],
        ]);

        $query = Log::query();

        if (!empty($validated['model'])) {
            $query->where('model', $validated['model']);
        }
        if (!empty($validated['action'])) {
            $query->where('action', $validated['action']);
        }
        if (!empty($validated['admin_id'])) {
            $query->where('admin_id', (int) $validated['admin_id']);
        }
        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }
        if (!empty($validated['date'])) {
            $query->whereDate('created_at', $validated['date']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('model', 'like', '%' . $search . '%')
                    ->orWhere('action', 'like', '%' . $search . '%')
                    ->orWhere('description', 'like', '%' . $search . '%')
                    ->orWhere('ip_address', 'like', '%' . $search . '%')
                    ->orWhere('user_agent', 'like', '%' . $search . '%');
            });
        }

        $logs = $query->latest()->paginate(10);

        $adminIds = collect($logs->items())->pluck('admin_id')->filter()->unique()->values();
        $employeeIds = collect($logs->items())->pluck('employee_id')->filter()->unique()->values();
        $admins = Admin::whereIn('id', $adminIds)->get()->keyBy('id');
        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');

        return response()->json([
            'status' => true,
            'message' => 'Logs fetched successfully.',
            'data' => collect($logs->items())->map(function (Log $log) use ($admins, $employees) {
                $admin = $admins->get((int) $log->admin_id);
                $employee = $employees->get((int) $log->employee_id);

                return [
                    'id' => $log->id,
                    'admin_id' => $log->admin_id,
                    'employee_id' => $log->employee_id,
                    'model' => $log->model,
                    'action' => $log->action,
                    'description' => $log->description,
                    'ip_address' => $log->ip_address,
                    'user_agent' => $log->user_agent,
                    'created_at' => $log->created_at,
                    'updated_at' => $log->updated_at,
                    'admin' => $admin ? [
                        'id' => $admin->id,
                        'full_name' => $admin->full_name,
                        'email' => $admin->email,
                        'role' => $admin->role,
                    ] : null,
                    'employee' => $employee ? [
                        'id' => $employee->id,
                        'emp_code' => $employee->emp_code,
                        'emp_name' => $employee->emp_name,
                        'emp_email' => $employee->emp_email,
                    ] : null,
                ];
            })->values()->all(),
            'pagination' => [
                'current_page' => $logs->currentPage(),
                'last_page' => $logs->lastPage(),
                'per_page' => $logs->perPage(),
                'total' => $logs->total(),
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
